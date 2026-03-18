"""Tests for check_append_invariant.py — one test per failure class."""
from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from check_append_invariant import check_append_invariant

VALID_ENTRY = {
    "schema_version": 1,
    "pack_root_sha256": "a" * 64,
    "pack_id": "pack_test",
    "receipt_integrity": "PASS",
    "claim_check": "PASS",
    "n_receipts": 1,
    "submitted_at": "2026-03-17T00:00:00+00:00",
    "source_repo": "Haserjian/test",
    "witness_status": "unwitnessed",
}


def _write_ledger(path: Path, entries: list[dict]) -> None:
    lines = [json.dumps(e, separators=(",", ":")) for e in entries]
    path.write_text("\n".join(lines) + "\n" if lines else "")


def _line_hash(entry: dict) -> str:
    line = json.dumps(entry, separators=(",", ":"))
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _entry_with_prev(base_entry: dict, **overrides) -> dict:
    e = deepcopy(VALID_ENTRY)
    e["pack_root_sha256"] = "b" * 64
    e["prev_entry_hash"] = _line_hash(base_entry)
    e.update(overrides)
    return e


# --- Happy path ---

class TestHappyPath:
    def test_valid_single_append(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        appended = _entry_with_prev(VALID_ENTRY)
        _write_ledger(candidate, [VALID_ENTRY, appended])

        result = check_append_invariant(base, candidate)
        assert result.ok, f"unexpected errors: {result.errors}"

    def test_first_entry_in_empty_ledger(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        base.write_text("")
        _write_ledger(candidate, [VALID_ENTRY])

        result = check_append_invariant(base, candidate)
        assert result.ok, f"unexpected errors: {result.errors}"

    def test_valid_append_with_scope_check(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        appended = _entry_with_prev(VALID_ENTRY)
        _write_ledger(candidate, [VALID_ENTRY, appended])

        result = check_append_invariant(base, candidate, changed_files=["ledger.jsonl"])
        assert result.ok, f"unexpected errors: {result.errors}"


# --- Failure: prior content mutation ---

class TestPriorContentMutation:
    def test_modified_earlier_line(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])

        mutated = deepcopy(VALID_ENTRY)
        mutated["n_receipts"] = 999
        appended = _entry_with_prev(mutated)
        _write_ledger(candidate, [mutated, appended])

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "prior_content_mutation"

    def test_deleted_earlier_line(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        entry2 = deepcopy(VALID_ENTRY)
        entry2["pack_root_sha256"] = "b" * 64
        _write_ledger(base, [VALID_ENTRY, entry2])
        _write_ledger(candidate, [entry2])  # removed first entry

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "prior_content_mutation"


# --- Failure: bad append shape ---

class TestAppendShape:
    def test_no_new_record(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        _write_ledger(candidate, [VALID_ENTRY])  # identical

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "no_append"

    def test_two_new_records(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        e2 = deepcopy(VALID_ENTRY)
        e2["pack_root_sha256"] = "b" * 64
        e2["prev_entry_hash"] = _line_hash(VALID_ENTRY)
        e3 = deepcopy(VALID_ENTRY)
        e3["pack_root_sha256"] = "c" * 64
        _write_ledger(candidate, [VALID_ENTRY, e2, e3])

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "multiple_appends"

    def test_appended_invalid_json(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        base_line = json.dumps(VALID_ENTRY, separators=(",", ":"))
        candidate.write_text(base_line + "\n" + "not json\n")
        base.write_text(base_line + "\n")

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "invalid_json"


# --- Failure: stale prev_entry_hash ---

class TestStalePrevHash:
    def test_wrong_prev_hash(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])

        stale = deepcopy(VALID_ENTRY)
        stale["pack_root_sha256"] = "b" * 64
        stale["prev_entry_hash"] = "f" * 64  # wrong hash
        _write_ledger(candidate, [VALID_ENTRY, stale])

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "stale_prev_hash"

    def test_missing_prev_hash_on_nonempty_base(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])

        no_prev = deepcopy(VALID_ENTRY)
        no_prev["pack_root_sha256"] = "b" * 64
        _write_ledger(candidate, [VALID_ENTRY, no_prev])

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "missing_prev_hash"


# --- Failure: file scope violation ---

class TestScopeViolation:
    def test_extra_files_touched(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        appended = _entry_with_prev(VALID_ENTRY)
        _write_ledger(candidate, [VALID_ENTRY, appended])

        result = check_append_invariant(
            base, candidate,
            changed_files=["ledger.jsonl", "README.md"],
        )
        assert not result.ok
        assert result.reason == "scope_violation"

    def test_only_ledger_passes_scope(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        _write_ledger(base, [VALID_ENTRY])
        appended = _entry_with_prev(VALID_ENTRY)
        _write_ledger(candidate, [VALID_ENTRY, appended])

        result = check_append_invariant(
            base, candidate,
            changed_files=["ledger.jsonl"],
        )
        assert result.ok


# --- Failure: newline / formatting ---

class TestNewlineHandling:
    def test_missing_terminal_newline(self, tmp_path: Path) -> None:
        base = tmp_path / "base.jsonl"
        candidate = tmp_path / "candidate.jsonl"
        base_line = json.dumps(VALID_ENTRY, separators=(",", ":"))
        base.write_text(base_line + "\n")
        appended = _entry_with_prev(VALID_ENTRY)
        appended_line = json.dumps(appended, separators=(",", ":"))
        candidate.write_text(base_line + "\n" + appended_line)  # no trailing \n

        result = check_append_invariant(base, candidate)
        assert not result.ok
        assert result.reason == "missing_terminal_newline"
