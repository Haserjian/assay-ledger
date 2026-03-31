#!/usr/bin/env python3
"""One-time migration: retroactively chain all ledger entries from genesis.

Entries 1-15 have no prev_entry_hash. Entries 16-20 have prev_entry_hash
values computed against the old (unchained) bytes of entry 15. After this
migration all 20 entries are rewritten with correct prev_entry_hash values
forming a single continuous chain from GENESIS_HASH to the tip.

This is a destructive one-time operation. Run only once, on the branch that
introduces genesis chaining. Verify with validate_ledger.py after running.

Usage:
    python scripts/migrate_genesis_chain.py [--ledger PATH] [--dry-run]
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from validate_ledger import GENESIS_HASH

DEFAULT_LEDGER = Path(__file__).parent.parent / "ledger.jsonl"


def _rechain(lines: list[str]) -> list[str]:
    """Rewrite all entries with correct prev_entry_hash from genesis.

    For each entry:
    - Remove any existing prev_entry_hash
    - Set prev_entry_hash = GENESIS_HASH for entry 1
    - Set prev_entry_hash = sha256(previous_new_line) for entries 2+
    - Append prev_entry_hash as the last field (matching existing convention)
    """
    result: list[str] = []
    prev_hash = GENESIS_HASH

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        entry = json.loads(line)

        # Remove existing prev_entry_hash so we control field position
        entry.pop("prev_entry_hash", None)

        # Serialize base entry, then inject prev_entry_hash at end
        base = json.dumps(entry, separators=(",", ":"))
        # Strip closing brace, append field, re-close
        new_line = base[:-1] + ',"prev_entry_hash":"' + prev_hash + '"}'

        result.append(new_line)
        prev_hash = hashlib.sha256(new_line.encode()).hexdigest()

    return result


def migrate(ledger_path: Path, dry_run: bool = False) -> None:
    if not ledger_path.exists():
        print(f"ERROR: {ledger_path} not found", file=sys.stderr)
        sys.exit(1)

    raw_lines = [l for l in ledger_path.read_text().splitlines() if l.strip()]
    print(f"Reading {len(raw_lines)} entries from {ledger_path}")

    new_lines = _rechain(raw_lines)

    if dry_run:
        print("Dry run — showing first and last entries:")
        print(f"  [1] {new_lines[0][:120]}...")
        print(f"  [{len(new_lines)}] {new_lines[-1][:120]}...")
        print("No files written.")
        return

    # Write atomically via temp file
    tmp = ledger_path.with_suffix(".jsonl.migrating")
    tmp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    tmp.replace(ledger_path)

    print(f"Wrote {len(new_lines)} entries to {ledger_path}")
    print(f"Genesis hash: {GENESIS_HASH}")
    print(f"Tip entry hash: {hashlib.sha256(new_lines[-1].encode()).hexdigest()}")
    print("Run: python validate_ledger.py   to verify")


def main() -> int:
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    if dry_run:
        args = [a for a in args if a != "--dry-run"]

    ledger_path = DEFAULT_LEDGER
    if "--ledger" in args:
        idx = args.index("--ledger")
        ledger_path = Path(args[idx + 1])

    migrate(ledger_path, dry_run=dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
