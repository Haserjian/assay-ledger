#!/usr/bin/env python3
"""Merge-time append invariant checker for the Assay Public Ledger.

Enforces the invariant defined in docs/LEDGER_APPEND_SEMANTICS.md:
  1. Append-only shape: prior records byte-identical, exactly one new record
  2. Chain freshness: prev_entry_hash matches SHA-256 of base tip
  3. File scope: only ledger.jsonl is modified

Exit 0 = valid append.  Exit 1 = invariant violation (with distinct reason).

Usage:
    python check_append_invariant.py <base_ledger> <candidate_ledger> [--changed-files FILE ...]

    base_ledger:       path to ledger.jsonl from the base branch (main)
    candidate_ledger:  path to ledger.jsonl from the merge candidate
    --changed-files:   list of files changed in the PR (optional; if provided,
                       enforces that only ledger.jsonl was modified)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from validate_ledger import GENESIS_HASH


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class CheckResult:
    """Structured result with distinct failure reasons."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.reason: str = ""  # primary failure category

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def fail(self, reason: str, message: str) -> None:
        if not self.reason:
            self.reason = reason
        self.errors.append(message)


# ---------------------------------------------------------------------------
# Core checks
# ---------------------------------------------------------------------------

ALLOWED_FILES = frozenset({"ledger.jsonl"})


def _read_lines(path: Path) -> list[str]:
    """Read file and return logical JSONL lines (non-empty, stripped)."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    return [line for line in raw.splitlines() if line.strip()]


def check_append_invariant(
    base_path: Path,
    candidate_path: Path,
    changed_files: list[str] | None = None,
) -> CheckResult:
    """Run all merge-time invariant checks.

    Args:
        base_path: ledger.jsonl from the base branch (main)
        candidate_path: ledger.jsonl from the merge candidate
        changed_files: list of changed file paths in the PR (optional)

    Returns a CheckResult with errors and reason if any check fails.
    """
    result = CheckResult()

    # --- 1. File scope ---
    if changed_files is not None:
        extra = set(changed_files) - ALLOWED_FILES
        if extra:
            result.fail(
                "scope_violation",
                f"PR modifies files outside ledger.jsonl: {sorted(extra)}",
            )

    # --- 2. Read base and candidate ---
    base_lines = _read_lines(base_path)
    candidate_lines = _read_lines(candidate_path)

    if not candidate_path.exists():
        result.fail("missing_candidate", "Candidate ledger.jsonl does not exist")
        return result

    # --- 3. Append-only shape: byte-identical prefix ---
    base_raw = base_path.read_text(encoding="utf-8") if base_path.exists() else ""
    candidate_raw = candidate_path.read_text(encoding="utf-8")

    # Compare logical lines for prefix identity
    if len(candidate_lines) < len(base_lines):
        result.fail(
            "prior_content_mutation",
            f"Candidate has fewer records ({len(candidate_lines)}) "
            f"than base ({len(base_lines)})",
        )
        return result

    for i, base_line in enumerate(base_lines):
        if i >= len(candidate_lines) or candidate_lines[i] != base_line:
            result.fail(
                "prior_content_mutation",
                f"Record {i + 1} differs between base and candidate "
                f"(byte-level comparison)",
            )
            return result

    # --- 4. Exactly one new record ---
    new_records = candidate_lines[len(base_lines):]
    if len(new_records) == 0:
        result.fail("no_append", "No new record appended")
        return result
    if len(new_records) > 1:
        result.fail(
            "multiple_appends",
            f"Expected exactly 1 new record, got {len(new_records)}",
        )
        return result

    appended_line = new_records[0]

    # --- 5. Appended record is valid JSON ---
    try:
        entry = json.loads(appended_line)
    except json.JSONDecodeError as exc:
        result.fail("invalid_json", f"Appended record is not valid JSON: {exc}")
        return result

    if not isinstance(entry, dict):
        result.fail("invalid_json", "Appended record is not a JSON object")
        return result

    # --- 6. Chain freshness: prev_entry_hash matches base tip or genesis ---
    prev_hash = entry.get("prev_entry_hash")
    if base_lines:
        expected_hash = hashlib.sha256(base_lines[-1].encode("utf-8")).hexdigest()
        if prev_hash is None:
            result.fail(
                "missing_prev_hash",
                "Appended record is missing prev_entry_hash "
                "(required: all entries participate in the hash chain)",
            )
        elif prev_hash != expected_hash:
            result.fail(
                "stale_prev_hash",
                f"prev_entry_hash mismatch: entry has {prev_hash[:16]}..., "
                f"base tip is {expected_hash[:16]}...",
            )
    else:
        # First-ever entry: must be anchored at GENESIS_HASH
        if prev_hash is None:
            result.fail(
                "missing_prev_hash",
                "First ledger entry must include prev_entry_hash = GENESIS_HASH",
            )
        elif prev_hash != GENESIS_HASH:
            result.fail(
                "wrong_genesis_hash",
                f"First entry prev_entry_hash must equal GENESIS_HASH "
                f"({GENESIS_HASH[:16]}...), got {prev_hash[:16]}...",
            )

    # --- 7. Terminal newline convention ---
    if candidate_raw and not candidate_raw.endswith("\n"):
        result.fail(
            "missing_terminal_newline",
            "Candidate ledger.jsonl does not end with a newline",
        )

    # Check for extra blank lines after the appended record
    trailing = candidate_raw[candidate_raw.rfind(appended_line) + len(appended_line):]
    if trailing.strip():
        result.fail(
            "trailing_content",
            "Unexpected content after the appended record",
        )

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    args = sys.argv[1:]
    changed_files: list[str] | None = None

    if "--changed-files" in args:
        idx = args.index("--changed-files")
        changed_files = args[idx + 1:]
        args = args[:idx]

    if len(args) != 2:
        print(
            "Usage: check_append_invariant.py <base_ledger> <candidate_ledger> "
            "[--changed-files FILE ...]",
            file=sys.stderr,
        )
        return 1

    base_path = Path(args[0])
    candidate_path = Path(args[1])

    result = check_append_invariant(base_path, candidate_path, changed_files)

    if result.ok:
        print("PASS: append invariant holds")
        return 0

    print(f"FAIL: {result.reason}")
    for err in result.errors:
        print(f"  - {err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
