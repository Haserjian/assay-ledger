#!/usr/bin/env python3
"""Create a signed checkpoint for ledger.jsonl.

A checkpoint binds the current ledger state (tip hash + entry count) to a
wall-clock timestamp and an Ed25519 signature. It is the first externally
verifiable anchor on top of the internally-consistent genesis chain.

Trust tier: same as pack signing — T0 (local self-generated key). The
checkpoint proves the ledger was not modified after signing; it does not
prove who the maintainer is. That requires T1 (CI-bound key).

Usage:
    python create_checkpoint.py [--ledger PATH] [--signer-id ID] [--dry-run]

    --ledger PATH       path to ledger.jsonl  (default: ./ledger.jsonl)
    --signer-id ID      key name in ~/.assay/keys/  (default: assay-local)
    --dry-run           print checkpoint JSON without writing

Output: checkpoints/checkpoint_NNNN.json (sequence-numbered, append-only)

Verify with:
    python verify_checkpoint.py checkpoints/checkpoint_NNNN.json
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from jcs import canonicalize

try:
    from nacl.signing import SigningKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

CHECKPOINT_VERSION = "1.0"
DEFAULT_SIGNER_ID = "assay-local"
DEFAULT_KEYS_DIR = Path.home() / ".assay" / "keys"
DEFAULT_LEDGER = Path(__file__).parent / "ledger.jsonl"
CHECKPOINTS_DIR = Path(__file__).parent / "checkpoints"


def _load_signing_key(signer_id: str, keys_dir: Path) -> "SigningKey":
    key_path = keys_dir / f"{signer_id}.key"
    if not key_path.exists():
        print(f"ERROR: signing key not found: {key_path}", file=sys.stderr)
        print(
            f"Generate one with: python -c \"from nacl.signing import SigningKey; "
            f"import os; k=SigningKey.generate(); "
            f"open('{key_path}','wb').write(k.encode()); "
            f"open('{keys_dir}/{signer_id}.pub','wb').write(k.verify_key.encode())\"",
            file=sys.stderr,
        )
        sys.exit(1)
    return SigningKey(key_path.read_bytes())


def _ledger_state(ledger_path: Path) -> tuple[int, str]:
    """Return (entry_count, tip_hash) for the ledger."""
    if not ledger_path.exists():
        print(f"ERROR: ledger not found: {ledger_path}", file=sys.stderr)
        sys.exit(1)
    lines = [l.strip() for l in ledger_path.read_text().splitlines() if l.strip()]
    if not lines:
        print("ERROR: ledger is empty", file=sys.stderr)
        sys.exit(1)
    tip_hash = hashlib.sha256(lines[-1].encode()).hexdigest()
    return len(lines), tip_hash


def _next_sequence(checkpoints_dir: Path) -> int:
    if not checkpoints_dir.exists():
        return 1
    existing = sorted(checkpoints_dir.glob("checkpoint_*.json"))
    if not existing:
        return 1
    last = existing[-1].stem  # "checkpoint_0001"
    try:
        return int(last.split("_")[1]) + 1
    except (IndexError, ValueError):
        return len(existing) + 1


def create_checkpoint(
    ledger_path: Path = DEFAULT_LEDGER,
    signer_id: str = DEFAULT_SIGNER_ID,
    keys_dir: Path = DEFAULT_KEYS_DIR,
    dry_run: bool = False,
) -> dict:
    if not NACL_AVAILABLE:
        print("ERROR: PyNaCl is required. Run: pip install pynacl", file=sys.stderr)
        sys.exit(1)

    entry_count, tip_hash = _ledger_state(ledger_path)
    sequence_number = _next_sequence(CHECKPOINTS_DIR)
    sk = _load_signing_key(signer_id, keys_dir)

    pubkey_bytes = sk.verify_key.encode()
    pubkey_b64 = base64.b64encode(pubkey_bytes).decode("ascii")
    pubkey_sha256 = hashlib.sha256(pubkey_bytes).hexdigest()

    checkpoint = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "sequence_number": sequence_number,
        "entry_count": entry_count,
        "tip_hash": tip_hash,
        "checkpoint_timestamp": datetime.now(timezone.utc).isoformat(),
        "signer_id": signer_id,
        "signer_pubkey": pubkey_b64,
        "signer_pubkey_sha256": pubkey_sha256,
    }

    # Sign JCS-canonical bytes of checkpoint (without signature field)
    canonical = canonicalize(checkpoint)
    sig_bytes = sk.sign(canonical).signature
    checkpoint["signature"] = base64.b64encode(sig_bytes).decode("ascii")

    if dry_run:
        print(json.dumps(checkpoint, indent=2))
        return checkpoint

    CHECKPOINTS_DIR.mkdir(exist_ok=True)
    out_path = CHECKPOINTS_DIR / f"checkpoint_{sequence_number:04d}.json"
    out_path.write_text(json.dumps(checkpoint, indent=2) + "\n")
    print(f"Checkpoint written: {out_path}")
    print(f"  entry_count={entry_count}  tip={tip_hash[:16]}...")
    print(f"  sequence={sequence_number}  signer={signer_id}")
    print(f"Verify: python verify_checkpoint.py {out_path}")
    return checkpoint


def main() -> int:
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    signer_id = DEFAULT_SIGNER_ID
    ledger_path = DEFAULT_LEDGER

    if "--signer-id" in args:
        idx = args.index("--signer-id")
        signer_id = args[idx + 1]
        args = args[:idx] + args[idx + 2:]

    if "--ledger" in args:
        idx = args.index("--ledger")
        ledger_path = Path(args[idx + 1])
        args = args[:idx] + args[idx + 2:]

    create_checkpoint(ledger_path=ledger_path, signer_id=signer_id, dry_run=dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
