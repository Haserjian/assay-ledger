#!/usr/bin/env python3
"""Verify a signed ledger checkpoint.

Checks:
  1. Required fields present and well-formed
  2. Ed25519 signature valid over JCS-canonical checkpoint (sans signature)
  3. signer_pubkey_sha256 matches sha256(pubkey)
  4. ledger entry_count matches checkpoint (truncation detection)
  5. ledger tip_hash matches checkpoint (rewrite detection)
  6. signer is in trusted registry with active status (when --registry PATH given)
  7. signer meets minimum trust tier (when --require-t1 given)

Exit 0 = valid.  Exit 1 = verification failure.

Usage:
    python verify_checkpoint.py <checkpoint.json> [--ledger PATH] [--registry PATH] [--require-t1]
    python verify_checkpoint.py checkpoints/checkpoint_0001.json
    python verify_checkpoint.py checkpoints/checkpoint_0001.json --ledger /path/to/ledger.jsonl
    python verify_checkpoint.py checkpoints/checkpoint_0001.json --registry signers.json --require-t1
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from jcs import canonicalize

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

DEFAULT_LEDGER = Path(__file__).parent / "ledger.jsonl"
DEFAULT_REGISTRY = Path(__file__).parent / "signers.json"

TRUST_TIER_ORDER = {"T0": 0, "T1": 1, "T2": 2}

REQUIRED_CHECKPOINT_FIELDS = {
    "checkpoint_version",
    "sequence_number",
    "entry_count",
    "tip_hash",
    "checkpoint_timestamp",
    "signer_id",
    "signer_pubkey",
    "signer_pubkey_sha256",
    "signature",
}


def _check_registry(
    checkpoint: dict,
    registry_path: Path,
    require_t1: bool,
) -> list[str]:
    """Verify signer is in the trusted registry with active status.

    Returns list of errors (empty = pass).
    """
    errors: list[str] = []

    if not registry_path.exists():
        errors.append(f"signer registry not found: {registry_path}")
        return errors

    try:
        registry = json.loads(registry_path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"signer registry is not valid JSON: {e}")
        return errors

    signers = {s["signer_id"]: s for s in registry.get("signers", [])}
    signer_id = checkpoint.get("signer_id", "")
    pubkey_sha = checkpoint.get("signer_pubkey_sha256", "")

    entry = signers.get(signer_id)
    if entry is None:
        errors.append(
            f"signer '{signer_id}' is not in the trusted registry — "
            "add an entry to signers.json and commit to main"
        )
        return errors

    if entry.get("status") != "active":
        errors.append(
            f"signer '{signer_id}' is not active in registry "
            f"(status={entry.get('status')!r})"
        )

    if entry.get("pubkey_sha256") != pubkey_sha:
        errors.append(
            f"registry pubkey_sha256 mismatch for signer '{signer_id}': "
            f"registry has {entry.get('pubkey_sha256', '')[:16]}..., "
            f"checkpoint has {pubkey_sha[:16]}..."
        )

    if require_t1:
        tier = entry.get("trust_tier", "T0")
        if TRUST_TIER_ORDER.get(tier, 0) < TRUST_TIER_ORDER["T1"]:
            errors.append(
                f"signer '{signer_id}' is trust tier {tier!r} — "
                "T1 or higher required (--require-t1 set). "
                "Provision a CI-bound key and add a T1 entry to signers.json."
            )

    return errors


def _ledger_state(ledger_path: Path) -> tuple[int, str] | None:
    """Return (entry_count, tip_hash) or None if ledger is missing/empty."""
    if not ledger_path.exists():
        return None
    lines = [l.strip() for l in ledger_path.read_text().splitlines() if l.strip()]
    if not lines:
        return None
    return len(lines), hashlib.sha256(lines[-1].encode()).hexdigest()


def verify_checkpoint(
    checkpoint_path: Path,
    ledger_path: Path = DEFAULT_LEDGER,
    registry_path: Path | None = None,
    require_t1: bool = False,
) -> tuple[bool, list[str]]:
    """Verify a checkpoint file against the current ledger state.

    Returns (ok: bool, errors: list[str]).
    Fail-closed: any missing field, bad signature, or ledger mismatch is an error.

    registry_path: if set, verify signer is in the trusted registry.
    require_t1: if True, reject checkpoints signed by sub-T1 signers.
    """
    errors: list[str] = []

    # --- Load checkpoint ---
    if not checkpoint_path.exists():
        return False, [f"checkpoint file not found: {checkpoint_path}"]

    try:
        checkpoint = json.loads(checkpoint_path.read_text())
    except json.JSONDecodeError as e:
        return False, [f"checkpoint is not valid JSON: {e}"]

    if not isinstance(checkpoint, dict):
        return False, ["checkpoint is not a JSON object"]

    # --- Required fields ---
    missing = REQUIRED_CHECKPOINT_FIELDS - set(checkpoint.keys())
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")

    if errors:
        return False, errors

    # --- Signature verification ---
    if not NACL_AVAILABLE:
        errors.append("PyNaCl not available — cannot verify Ed25519 signature")
        return False, errors

    try:
        pubkey_bytes = base64.b64decode(checkpoint["signer_pubkey"])
        sig_bytes = base64.b64decode(checkpoint["signature"])
    except Exception as e:
        errors.append(f"base64 decode failed for pubkey or signature: {e}")
        return False, errors

    # Reconstruct unsigned checkpoint (same fields, without signature)
    unsigned = {k: v for k, v in checkpoint.items() if k != "signature"}
    canonical = canonicalize(unsigned)

    try:
        vk = VerifyKey(pubkey_bytes)
        vk.verify(canonical, sig_bytes)
    except BadSignatureError:
        errors.append("Ed25519 signature verification FAILED — checkpoint may be tampered")
        return False, errors
    except Exception as e:
        errors.append(f"Ed25519 verification error: {e}")
        return False, errors

    # --- signer_pubkey_sha256 consistency ---
    computed_sha = hashlib.sha256(pubkey_bytes).hexdigest()
    if computed_sha != checkpoint["signer_pubkey_sha256"]:
        errors.append(
            f"signer_pubkey_sha256 mismatch: "
            f"computed {computed_sha[:16]}... != checkpoint {checkpoint['signer_pubkey_sha256'][:16]}..."
        )
        return False, errors

    # --- Ledger state checks ---
    state = _ledger_state(ledger_path)
    if state is None:
        errors.append(f"ledger not found or empty: {ledger_path}")
        return False, errors

    current_count, current_tip = state
    cp_count = checkpoint["entry_count"]
    cp_tip = checkpoint["tip_hash"]

    if current_count < cp_count:
        errors.append(
            f"TRUNCATION DETECTED: ledger has {current_count} entries, "
            f"checkpoint expects {cp_count}"
        )

    if current_tip != cp_tip:
        errors.append(
            f"TIP MISMATCH: ledger tip is {current_tip[:16]}..., "
            f"checkpoint has {cp_tip[:16]}... — "
            "chain may have been rewritten or a newer checkpoint exists"
        )

    if errors:
        return False, errors

    # --- Registry check (optional) ---
    if registry_path is not None:
        reg_errors = _check_registry(checkpoint, registry_path, require_t1)
        if reg_errors:
            errors.extend(reg_errors)
            return False, errors

    return True, []


def main() -> int:
    args = sys.argv[1:]
    ledger_path = DEFAULT_LEDGER
    registry_path: Path | None = None
    require_t1 = False

    if "--require-t1" in args:
        require_t1 = True
        args = [a for a in args if a != "--require-t1"]

    if "--registry" in args:
        idx = args.index("--registry")
        registry_path = Path(args[idx + 1])
        args = args[:idx] + args[idx + 2:]
    elif (Path(__file__).parent / "signers.json").exists():
        # Auto-load registry if it exists alongside this script
        registry_path = DEFAULT_REGISTRY

    if "--ledger" in args:
        idx = args.index("--ledger")
        ledger_path = Path(args[idx + 1])
        args = args[:idx] + args[idx + 2:]

    if not args:
        print(
            "Usage: python verify_checkpoint.py <checkpoint.json> "
            "[--ledger PATH] [--registry PATH] [--require-t1]",
            file=sys.stderr,
        )
        return 1

    checkpoint_path = Path(args[0])
    ok, errors = verify_checkpoint(
        checkpoint_path, ledger_path,
        registry_path=registry_path,
        require_t1=require_t1,
    )

    if ok:
        cp = json.loads(checkpoint_path.read_text())
        tier_note = ""
        if registry_path is not None:
            try:
                reg = json.loads(registry_path.read_text())
                signers = {s["signer_id"]: s for s in reg.get("signers", [])}
                entry = signers.get(cp.get("signer_id", ""), {})
                tier_note = f"  trust_tier={entry.get('trust_tier', 'unknown')}"
            except Exception:
                pass
        print(
            f"PASS: checkpoint {cp.get('sequence_number')} verified\n"
            f"  entry_count={cp['entry_count']}  "
            f"tip={cp['tip_hash'][:16]}...  "
            f"signer={cp['signer_id']}{tier_note}"
        )
        return 0

    print(f"FAIL: checkpoint verification failed ({len(errors)} error(s))")
    for e in errors:
        print(f"  - {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
