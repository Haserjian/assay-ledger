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

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER_PATH = Path(__file__).parent / "ledger.jsonl"


def extract_entry(pack_dir: Path, source_repo: str) -> dict:
    """Extract a ledger entry from a pack manifest."""
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())
    att = manifest.get("attestation", {})

    # Required fields
    entry = {
        "schema_version": 1,
        "pack_root_sha256": manifest.get("pack_root_sha256", manifest.get("attestation_sha256", "")),
        "pack_id": att.get("pack_id", manifest.get("pack_id", "")),
        "receipt_integrity": att.get("receipt_integrity", "UNKNOWN"),
        "claim_check": att.get("claim_check", "N/A"),
        "n_receipts": att.get("n_receipts", 0),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "source_repo": source_repo,
    }

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

    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    print(f"Submitted: {entry['pack_root_sha256'][:16]}... ({entry['pack_id']})")
    print(f"  integrity={entry['receipt_integrity']} claims={entry['claim_check']} receipts={entry['n_receipts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
