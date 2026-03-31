"""Tests for create_checkpoint.py and verify_checkpoint.py.

Each test represents a distinct trust failure mode or invariant.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from jcs import canonicalize
from verify_checkpoint import verify_checkpoint

try:
    from nacl.signing import SigningKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

pytestmark = pytest.mark.skipif(not NACL_AVAILABLE, reason="PyNaCl required")

# --- Fixtures ---

def _make_signing_key() -> "SigningKey":
    return SigningKey.generate()


def _make_ledger(tmp_path: Path, n_entries: int = 3) -> Path:
    """Write a minimal valid genesis-chained ledger."""
    from validate_ledger import GENESIS_HASH
    ledger = tmp_path / "ledger.jsonl"
    lines: list[str] = []
    prev_hash = GENESIS_HASH
    for i in range(n_entries):
        entry = {
            "schema_version": 1,
            "pack_root_sha256": hashlib.sha256(f"entry{i}".encode()).hexdigest(),
            "pack_id": f"pack_test_{i:04d}",
            "receipt_integrity": "PASS",
            "claim_check": "PASS",
            "n_receipts": 1,
            "submitted_at": "2026-03-31T00:00:00+00:00",
            "source_repo": "Haserjian/test",
            "witness_status": "unwitnessed",
            "prev_entry_hash": prev_hash,
        }
        line = json.dumps(entry, separators=(",", ":"))
        lines.append(line)
        prev_hash = hashlib.sha256(line.encode()).hexdigest()
    ledger.write_text("\n".join(lines) + "\n")
    return ledger


def _make_checkpoint(
    sk: "SigningKey",
    ledger_path: Path,
    sequence_number: int = 1,
) -> dict:
    """Create a valid signed checkpoint dict for the given ledger."""
    lines = [l.strip() for l in ledger_path.read_text().splitlines() if l.strip()]
    entry_count = len(lines)
    tip_hash = hashlib.sha256(lines[-1].encode()).hexdigest()

    pubkey_bytes = sk.verify_key.encode()
    checkpoint = {
        "checkpoint_version": "1.0",
        "sequence_number": sequence_number,
        "entry_count": entry_count,
        "tip_hash": tip_hash,
        "checkpoint_timestamp": datetime.now(timezone.utc).isoformat(),
        "signer_id": "test-signer",
        "signer_pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
        "signer_pubkey_sha256": hashlib.sha256(pubkey_bytes).hexdigest(),
    }
    sig_bytes = sk.sign(canonicalize(checkpoint)).signature
    checkpoint["signature"] = base64.b64encode(sig_bytes).decode("ascii")
    return checkpoint


def _write_checkpoint(tmp_path: Path, cp: dict, name: str = "checkpoint.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(cp, indent=2))
    return p


# --- Happy path ---

class TestHappyPath:
    def test_valid_checkpoint_passes(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path)
        cp = _make_checkpoint(sk, ledger)
        cp_path = _write_checkpoint(tmp_path, cp)

        ok, errors = verify_checkpoint(cp_path, ledger)
        assert ok, f"unexpected errors: {errors}"

    def test_checkpoint_binds_entry_count(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=7)
        cp = _make_checkpoint(sk, ledger)
        assert cp["entry_count"] == 7

    def test_checkpoint_binds_tip_hash(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        lines = [l.strip() for l in ledger.read_text().splitlines() if l.strip()]
        expected_tip = hashlib.sha256(lines[-1].encode()).hexdigest()

        cp = _make_checkpoint(sk, ledger)
        assert cp["tip_hash"] == expected_tip


# --- Truncation detection ---

class TestTruncation:
    def test_ledger_shorter_than_checkpoint_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=5)
        cp = _make_checkpoint(sk, ledger)

        # Truncate ledger to 3 entries
        lines = [l.strip() for l in ledger.read_text().splitlines() if l.strip()]
        ledger.write_text("\n".join(lines[:3]) + "\n")

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("TRUNCATION" in e.upper() or "truncation" in e.lower() for e in errors), \
            f"expected truncation error, got: {errors}"

    def test_empty_ledger_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)

        ledger.write_text("")  # wipe it

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok

    def test_missing_ledger_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)

        absent = tmp_path / "does_not_exist.jsonl"
        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, absent)
        assert not ok


# --- Chain rewrite detection ---

class TestChainRewrite:
    def test_tip_hash_mismatch_fails(self, tmp_path):
        """Ledger rewritten after checkpoint — tip hash differs."""
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)

        # Append a new entry to change the tip
        lines = [l.strip() for l in ledger.read_text().splitlines() if l.strip()]
        prev_hash = hashlib.sha256(lines[-1].encode()).hexdigest()
        from validate_ledger import GENESIS_HASH  # noqa: F401
        extra_entry = {
            "schema_version": 1,
            "pack_root_sha256": "e" * 64,
            "pack_id": "pack_extra",
            "receipt_integrity": "PASS",
            "claim_check": "PASS",
            "n_receipts": 1,
            "submitted_at": "2026-03-31T00:00:00+00:00",
            "source_repo": "Haserjian/test",
            "witness_status": "unwitnessed",
            "prev_entry_hash": prev_hash,
        }
        ledger.write_text(
            "\n".join(lines) + "\n" +
            json.dumps(extra_entry, separators=(",", ":")) + "\n"
        )

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("TIP MISMATCH" in e.upper() or "tip" in e.lower() for e in errors), \
            f"expected tip mismatch error, got: {errors}"


# --- Signature failures ---

class TestSignatureFailure:
    def test_tampered_entry_count_fails(self, tmp_path):
        """Changing a checkpoint field after signing invalidates signature."""
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)
        cp["entry_count"] = 99  # tamper after signing

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("signature" in e.lower() for e in errors), \
            f"expected signature error, got: {errors}"

    def test_tampered_tip_hash_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)
        cp["tip_hash"] = "f" * 64  # tamper

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("signature" in e.lower() for e in errors)

    def test_corrupted_signature_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)
        cp["signature"] = base64.b64encode(b"\x00" * 64).decode()  # bad sig

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("signature" in e.lower() for e in errors)

    def test_wrong_key_fails(self, tmp_path):
        """Checkpoint signed with key A, verified with mismatched pubkey B."""
        sk_a = _make_signing_key()
        sk_b = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)

        cp = _make_checkpoint(sk_a, ledger)
        # Replace pubkey with sk_b's key — pubkey/signature pair mismatch
        cp["signer_pubkey"] = base64.b64encode(sk_b.verify_key.encode()).decode()
        cp["signer_pubkey_sha256"] = hashlib.sha256(sk_b.verify_key.encode()).hexdigest()

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("signature" in e.lower() for e in errors)


# --- Malformed checkpoint ---

class TestMalformedCheckpoint:
    def test_missing_required_field_fails(self, tmp_path):
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)
        del cp["tip_hash"]

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("tip_hash" in e for e in errors)

    def test_invalid_json_fails(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all")
        ok, errors = verify_checkpoint(bad, tmp_path / "ledger.jsonl")
        assert not ok
        assert any("JSON" in e for e in errors)

    def test_missing_checkpoint_file_fails(self, tmp_path):
        ok, errors = verify_checkpoint(tmp_path / "missing.json", tmp_path / "ledger.jsonl")
        assert not ok
        assert any("not found" in e for e in errors)

    def test_signer_pubkey_sha256_mismatch_fails(self, tmp_path):
        """signer_pubkey_sha256 doesn't match the actual pubkey bytes."""
        sk = _make_signing_key()
        ledger = _make_ledger(tmp_path, n_entries=3)
        cp = _make_checkpoint(sk, ledger)
        cp["signer_pubkey_sha256"] = "a" * 64  # wrong hash
        # Re-sign so signature is valid but pubkey hash is wrong
        cp_no_sig = {k: v for k, v in cp.items() if k != "signature"}
        cp["signature"] = base64.b64encode(
            sk.sign(canonicalize(cp_no_sig)).signature
        ).decode()

        cp_path = _write_checkpoint(tmp_path, cp)
        ok, errors = verify_checkpoint(cp_path, ledger)
        assert not ok
        assert any("signer_pubkey_sha256" in e for e in errors)
