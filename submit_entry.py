#!/usr/bin/env python3
"""Submit a Proof Pack attestation to the ledger.

Usage:
    python submit_entry.py <pack_dir> <source_repo>
    python submit_entry.py ./proof_pack_abc123/ Haserjian/ccio

Reads pack_manifest.json from the pack, extracts the attestation fingerprint,
and appends a new JSONL line to ledger.jsonl.

Idempotent: if pack_root_sha256 already exists in the ledger, prints a message
and exits 0 without duplicating.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER_PATH = Path(__file__).parent / "ledger.jsonl"
VALID_RECEIPT_INTEGRITY = {"PASS", "FAIL"}


def extract_entry(pack_dir: Path, source_repo: str) -> dict:
    """Extract a ledger entry from a pack manifest."""
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())
    att = manifest.get("attestation", {})
    if not isinstance(att, dict):
        att = {}

    receipt_integrity = att.get("receipt_integrity")
    if receipt_integrity not in VALID_RECEIPT_INTEGRITY:
        print(
            "ERROR: pack manifest must include attestation.receipt_integrity as PASS or FAIL",
            file=sys.stderr,
        )
        sys.exit(1)

    # Required fields
    entry = {
        "schema_version": 1,
        "pack_root_sha256": manifest.get("pack_root_sha256", manifest.get("attestation_sha256", "")),
        "pack_id": att.get("pack_id", manifest.get("pack_id", "")),
        "receipt_integrity": receipt_integrity,
        "claim_check": att.get("claim_check", "N/A"),
        "n_receipts": att.get("n_receipts", 0),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "source_repo": source_repo,
    }

    # Witness status: re-verify pack manifest cryptographically
    # Import the ledger's own witness_verify module for independent re-verification
    from witness_verify import witness_verify

    manifest_b64 = base64.b64encode(manifest_path.read_bytes()).decode()
    pack_root = entry["pack_root_sha256"]
    wresult = witness_verify(manifest_b64, pack_root)
    entry["witness_status"] = wresult.witness_status

    # Optional fields: only include when non-empty
    for key, val in [
        ("mode", att.get("mode")),
        ("assurance_level", att.get("assurance_level")),
        ("timestamp_start", att.get("timestamp_start")),
        ("timestamp_end", att.get("timestamp_end")),
        ("signer_pubkey_sha256", manifest.get("signer_pubkey_sha256")),
        ("verifier_version", att.get("verifier_version")),
    ]:
        if val:
            entry[key] = val

    return entry


def _last_line_hash() -> str | None:
    """Return SHA-256 of the last non-empty line in the ledger, or None."""
    if not LEDGER_PATH.exists():
        return None
    last_line = ""
    with open(LEDGER_PATH) as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                last_line = stripped
    if not last_line:
        return None
    return hashlib.sha256(last_line.encode()).hexdigest()


def already_in_ledger(root_sha256: str) -> bool:
    """Check if this pack_root_sha256 is already in the ledger."""
    if not LEDGER_PATH.exists():
        return False
    with open(LEDGER_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("pack_root_sha256") == root_sha256:
                    return True
            except json.JSONDecodeError:
                continue
    return False


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python submit_entry.py <pack_dir> <source_repo>", file=sys.stderr)
        return 1

    pack_dir = Path(sys.argv[1])
    source_repo = sys.argv[2]

    entry = extract_entry(pack_dir, source_repo)

    if already_in_ledger(entry["pack_root_sha256"]):
        print(f"Already in ledger: {entry['pack_root_sha256'][:16]}... ({entry['pack_id']})")
        return 0

    # Compute prev_entry_hash from last line of ledger (hash chain)
    prev_hash = _last_line_hash()
    if prev_hash:
        entry["prev_entry_hash"] = prev_hash

    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    print(f"Submitted: {entry['pack_root_sha256'][:16]}... ({entry['pack_id']})")
    print(f"  integrity={entry['receipt_integrity']} claims={entry['claim_check']} receipts={entry['n_receipts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
