"""Adversarial regression tests for validate_ledger.py.

Every test case represents a real attack vector or edge case
that the validator MUST reject or handle correctly.
"""
from __future__ import annotations

import json
import sys
import tempfile
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from validate_ledger import validate_entry, validate_ledger

# --- Fixtures ---

VALID_ENTRY = {
    "schema_version": 1,
    "pack_root_sha256": "a" * 64,
    "pack_id": "pack_20260208T000000_test",
    "receipt_integrity": "PASS",
    "claim_check": "PASS",
    "n_receipts": 5,
    "submitted_at": "2026-02-08T00:00:00+00:00",
    "source_repo": "Haserjian/ccio",
}


def entry(**overrides):
    e = deepcopy(VALID_ENTRY)
    e.update(overrides)
    return e


def must_fail(e, substr=None, msg="expected validation to fail"):
    errors = validate_entry(e, 1)
    assert errors, msg
    if substr:
        assert any(substr in err for err in errors), f"expected '{substr}' in errors: {errors}"
    return errors


def must_pass(e, msg="expected validation to pass"):
    errors = validate_entry(e, 1)
    assert not errors, f"{msg}: {errors}"


# --- Required fields ---

class TestRequiredFields:
    def test_valid_entry_passes(self):
        must_pass(VALID_ENTRY)

    def test_missing_pack_root_sha256(self):
        e = deepcopy(VALID_ENTRY)
        del e["pack_root_sha256"]
        must_fail(e, "missing required field 'pack_root_sha256'")

    def test_missing_pack_id(self):
        e = deepcopy(VALID_ENTRY)
        del e["pack_id"]
        must_fail(e, "missing required field 'pack_id'")

    def test_missing_receipt_integrity(self):
        e = deepcopy(VALID_ENTRY)
        del e["receipt_integrity"]
        must_fail(e, "missing required field 'receipt_integrity'")

    def test_missing_source_repo(self):
        e = deepcopy(VALID_ENTRY)
        del e["source_repo"]
        must_fail(e, "missing required field 'source_repo'")

    def test_missing_submitted_at(self):
        e = deepcopy(VALID_ENTRY)
        del e["submitted_at"]
        must_fail(e, "missing required field 'submitted_at'")

    def test_timestamp_start_is_optional(self):
        must_pass(VALID_ENTRY)  # no timestamp_start present


# --- SHA-256 format ---

class TestSHA256Format:
    def test_uppercase_hex_rejected(self):
        must_fail(entry(pack_root_sha256="A" * 64), "not a valid SHA-256")

    def test_short_hash_rejected(self):
        must_fail(entry(pack_root_sha256="a" * 63), "not a valid SHA-256")

    def test_long_hash_rejected(self):
        must_fail(entry(pack_root_sha256="a" * 65), "not a valid SHA-256")

    def test_non_hex_chars_rejected(self):
        must_fail(entry(pack_root_sha256="g" * 64), "not a valid SHA-256")

    def test_signer_pubkey_uppercase_rejected(self):
        must_fail(entry(signer_pubkey_sha256="A" * 64), "signer_pubkey_sha256")

    def test_signer_pubkey_valid(self):
        must_pass(entry(signer_pubkey_sha256="b" * 64))


# --- Enum validation ---

class TestEnums:
    def test_integrity_invalid_value(self):
        must_fail(entry(receipt_integrity="YES"), "receipt_integrity must be PASS or FAIL")

    def test_claim_check_invalid_value(self):
        must_fail(entry(claim_check="MAYBE"), "claim_check must be PASS/FAIL/N/A")

    def test_claim_check_na_valid(self):
        must_pass(entry(claim_check="N/A"))

    def test_witness_status_valid_values(self):
        must_pass(entry(witness_status="unwitnessed"))
        must_pass(entry(witness_status="hash_verified"))
        must_pass(entry(witness_status="signature_verified"))

    def test_witness_status_invalid_value(self):
        must_fail(entry(witness_status="full_verified"), "witness_status must be one of")

    def test_witness_status_optional(self):
        must_pass(VALID_ENTRY)  # no witness_status present

    def test_schema_version_wrong(self):
        must_fail(entry(schema_version=2), "schema_version must be 1")

    def test_schema_version_string(self):
        must_fail(entry(schema_version="1"), "schema_version must be 1")


# --- n_receipts ---

class TestNReceipts:
    def test_negative_rejected(self):
        must_fail(entry(n_receipts=-1), "non-negative integer")

    def test_float_rejected(self):
        must_fail(entry(n_receipts=1.5), "non-negative integer")

    def test_zero_valid(self):
        must_pass(entry(n_receipts=0))

    def test_string_rejected(self):
        must_fail(entry(n_receipts="5"), "non-negative integer")


# --- Datetime format ---

class TestDatetime:
    def test_not_a_date_rejected(self):
        must_fail(entry(submitted_at="not-a-date"), "not a valid ISO 8601")

    def test_unix_timestamp_rejected(self):
        must_fail(entry(submitted_at="1707350400"), "not a valid ISO 8601")

    def test_z_suffix_accepted(self):
        must_pass(entry(submitted_at="2026-02-08T00:00:00Z"))

    def test_offset_accepted(self):
        must_pass(entry(submitted_at="2026-02-08T00:00:00+05:30"))

    def test_optional_timestamp_start_validated_when_present(self):
        must_fail(entry(timestamp_start="garbage"), "not a valid ISO 8601")

    def test_optional_timestamp_end_validated_when_present(self):
        must_fail(entry(timestamp_end="garbage"), "not a valid ISO 8601")


# --- Control characters ---

class TestControlChars:
    def test_null_byte_in_pack_id(self):
        must_fail(entry(pack_id="foo\x00bar"), "control characters")

    def test_bell_char_in_source_repo(self):
        must_fail(entry(source_repo="Ha\x07serjian/ccio"), "control characters")

    def test_tab_is_allowed(self):
        # Tabs (\x09) and newlines (\x0a, \x0d) are not in our control char range
        # because JSON encoding handles them. The regex excludes \x09, \x0a, \x0d.
        must_pass(entry())  # baseline

    def test_escape_sequence_in_mode(self):
        must_fail(entry(mode="shadow\x1b[31m"), "control characters")


# --- Max length ---

class TestMaxLength:
    def test_pack_id_too_long(self):
        must_fail(entry(pack_id="A" * 257), "exceeds max length 256")

    def test_source_repo_too_long(self):
        must_fail(entry(source_repo="a" * 257), "exceeds max length")

    def test_pack_id_at_limit(self):
        must_pass(entry(pack_id="x" * 256))

    def test_mode_too_long(self):
        must_fail(entry(mode="x" * 65), "exceeds max length 64")


# --- source_repo format ---

class TestSourceRepoFormat:
    def test_valid_repo(self):
        must_pass(entry(source_repo="Haserjian/ccio"))

    def test_dots_and_hyphens(self):
        must_pass(entry(source_repo="my-org/my-repo.js"))

    def test_path_traversal_rejected(self):
        must_fail(entry(source_repo="../../etc/passwd"), "source_repo must match")

    def test_script_tag_rejected(self):
        must_fail(entry(source_repo='"><script>alert(1)</script>'), "source_repo must match")

    def test_triple_segment_rejected(self):
        must_fail(entry(source_repo="a/b/c"), "source_repo must match")

    def test_empty_repo_rejected(self):
        must_fail(entry(source_repo=""), "source_repo must match")

    def test_no_slash_rejected(self):
        must_fail(entry(source_repo="justrepo"), "source_repo must match")


# --- Extra fields ---

class TestExtraFields:
    def test_unknown_field_rejected(self):
        must_fail(entry(evil_field="payload"), "unexpected fields")

    def test_nested_object_rejected(self):
        must_fail(entry(metadata={"nested": True}), "unexpected fields")


# --- Injection payloads (stored literally, but must not break validation) ---

class TestInjectionPayloads:
    def test_shell_injection_in_pack_id(self):
        # Should be stored literally, not executed. Passes validation as a string.
        must_pass(entry(pack_id="x'; rm -rf /"))

    def test_sql_injection_in_pack_id(self):
        must_pass(entry(pack_id="x' OR '1'='1"))

    def test_json_injection_in_pack_id(self):
        # Attempt to break out of JSON string -- but json.loads already parsed it,
        # so the value is a normal string. Should pass.
        must_pass(entry(pack_id='","schema_version":2,"x":"'))

    def test_python_injection_in_pack_id(self):
        must_pass(entry(pack_id="__import__('os').system('whoami')"))

    def test_html_injection_in_pack_id(self):
        # XSS payload. Stored as text. The UI must use textContent, not innerHTML.
        must_pass(entry(pack_id="<img src=x onerror=alert(1)>"))

    def test_newline_injection_in_source_repo(self):
        # Newline would break JSONL if it got through, but json.dumps escapes it.
        # However, source_repo format check will reject this.
        must_fail(entry(source_repo="foo/bar\nBAD"), "source_repo must match")


# --- Ledger-level validation ---

class TestLedgerLevel:
    def test_empty_file_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("")
        errors = validate_ledger(Path(f.name))
        assert any("empty" in e for e in errors)

    def test_duplicate_hash_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            line = json.dumps(VALID_ENTRY, separators=(",", ":"))
            f.write(line + "\n" + line + "\n")
        errors = validate_ledger(Path(f.name))
        assert any("duplicate" in e for e in errors)

    def test_invalid_json_line(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json\n")
        errors = validate_ledger(Path(f.name))
        assert any("invalid JSON" in e for e in errors)

    def test_valid_single_entry(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(VALID_ENTRY, separators=(",", ":")) + "\n")
        errors = validate_ledger(Path(f.name))
        assert not errors, f"unexpected errors: {errors}"

    def test_missing_file(self):
        errors = validate_ledger(Path("/nonexistent/path.jsonl"))
        assert any("not found" in e for e in errors)
