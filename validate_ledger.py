#!/usr/bin/env python3
"""Validate ledger.jsonl against the schema and check invariants.

Exit 0 = valid, Exit 1 = validation error.
Used by CI to gate all ledger PRs.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "ledger.schema.json"
LEDGER_PATH = Path(__file__).parent / "ledger.jsonl"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SOURCE_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
VALID_INTEGRITY = {"PASS", "FAIL"}
VALID_CLAIM = {"PASS", "FAIL", "N/A"}
VALID_WITNESS = {"unwitnessed", "hash_verified", "signature_verified"}

# Max lengths for string fields (bytes)
MAX_LENGTHS = {
    "pack_id": 256,
    "source_repo": 256,
    "source_workflow": 512,
    "mode": 64,
    "assurance_level": 16,
    "verifier_version": 64,
}

REQUIRED_FIELDS = {
    "schema_version",
    "pack_root_sha256",
    "pack_id",
    "receipt_integrity",
    "claim_check",
    "n_receipts",
    "submitted_at",
    "source_repo",
}

OPTIONAL_FIELDS = {
    "timestamp_start",
    "timestamp_end",
    "mode",
    "assurance_level",
    "source_workflow",
    "signer_pubkey_sha256",
    "verifier_version",
    "witness_status",
}

ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS


def validate_entry(entry: dict, line_num: int) -> list[str]:
    """Validate a single ledger entry. Returns list of error strings."""
    errors: list[str] = []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in entry:
            errors.append(f"line {line_num}: missing required field '{field}'")

    # Check no extra fields
    extra = set(entry.keys()) - ALL_FIELDS
    if extra:
        errors.append(f"line {line_num}: unexpected fields: {extra}")

    # Schema version
    if entry.get("schema_version") != 1:
        errors.append(f"line {line_num}: schema_version must be 1, got {entry.get('schema_version')}")

    # SHA-256 format
    root = entry.get("pack_root_sha256", "")
    if not SHA256_RE.match(root):
        errors.append(f"line {line_num}: pack_root_sha256 is not a valid SHA-256 hex string")

    signer = entry.get("signer_pubkey_sha256")
    if signer is not None and not SHA256_RE.match(signer):
        errors.append(f"line {line_num}: signer_pubkey_sha256 is not a valid SHA-256 hex string")

    # Enum checks
    integrity = entry.get("receipt_integrity")
    if integrity is not None and integrity not in VALID_INTEGRITY:
        errors.append(f"line {line_num}: receipt_integrity must be PASS or FAIL, got '{integrity}'")

    claim = entry.get("claim_check")
    if claim is not None and claim not in VALID_CLAIM:
        errors.append(f"line {line_num}: claim_check must be PASS/FAIL/N/A, got '{claim}'")

    # n_receipts
    n = entry.get("n_receipts")
    if n is not None and (not isinstance(n, int) or n < 0):
        errors.append(f"line {line_num}: n_receipts must be a non-negative integer")

    # ISO datetime format validation
    for dt_field in ("submitted_at", "timestamp_start", "timestamp_end"):
        dt_val = entry.get(dt_field)
        if dt_val is not None:
            try:
                s = dt_val
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                datetime.fromisoformat(s)
            except (ValueError, TypeError):
                errors.append(f"line {line_num}: {dt_field} is not a valid ISO 8601 datetime")

    # witness_status enum
    witness = entry.get("witness_status")
    if witness is not None and witness not in VALID_WITNESS:
        errors.append(f"line {line_num}: witness_status must be one of {VALID_WITNESS}, got '{witness}'")

    # Control character rejection (all string values)
    for key, val in entry.items():
        if isinstance(val, str) and CONTROL_CHAR_RE.search(val):
            errors.append(f"line {line_num}: field '{key}' contains control characters")

    # Max length checks
    for field, max_len in MAX_LENGTHS.items():
        val = entry.get(field)
        if isinstance(val, str) and len(val) > max_len:
            errors.append(f"line {line_num}: field '{field}' exceeds max length {max_len} (got {len(val)})")

    # source_repo format (owner/repo, alphanumeric + dots/hyphens/underscores)
    repo = entry.get("source_repo")
    if isinstance(repo, str) and not SOURCE_REPO_RE.match(repo):
        errors.append(f"line {line_num}: source_repo must match 'owner/repo' format")

    return errors


def validate_ledger(path: Path) -> list[str]:
    """Validate entire ledger file. Returns list of all errors."""
    if not path.exists():
        return ["ledger.jsonl not found"]

    errors: list[str] = []
    seen_roots: dict[str, int] = {}

    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"line {line_num}: invalid JSON: {e}")
                continue

            errors.extend(validate_entry(entry, line_num))

            # Uniqueness: pack_root_sha256 must not repeat
            root = entry.get("pack_root_sha256", "")
            if root in seen_roots:
                errors.append(
                    f"line {line_num}: duplicate pack_root_sha256 "
                    f"(first seen on line {seen_roots[root]})"
                )
            else:
                seen_roots[root] = line_num

    if not seen_roots:
        errors.append("ledger.jsonl is empty")

    return errors


def main() -> int:
    ledger = Path(sys.argv[1]) if len(sys.argv) > 1 else LEDGER_PATH
    errors = validate_ledger(ledger)

    if errors:
        print(f"FAIL: {len(errors)} validation error(s):")
        for e in errors:
            print(f"  - {e}")
        return 1

    # Count entries
    with open(ledger) as f:
        count = sum(1 for line in f if line.strip())
    print(f"PASS: {count} ledger entries validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
