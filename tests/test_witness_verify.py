"""Tests for witness_verify.py L2 signature verification."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from witness_verify import witness_verify, WitnessResult

# Use a real corpus pack manifest if available, otherwise skip
CORPUS_MANIFEST = Path.home() / "ccio/conformance/corpus_v1/packs/good_01/pack_manifest.json"


def _load_manifest_b64_and_root():
    """Load a real pack manifest as base64 and extract root hash."""
    if not CORPUS_MANIFEST.exists():
        return None, None
    manifest = json.loads(CORPUS_MANIFEST.read_text())
    b64 = base64.b64encode(CORPUS_MANIFEST.read_bytes()).decode()
    root = manifest["pack_root_sha256"]
    return b64, root


def _make_fake_manifest(**overrides):
    """Create a minimal valid-looking manifest (no real signature)."""
    from jcs import canonicalize
    att = {
        "pack_id": "test_pack",
        "receipt_integrity": "PASS",
        "claim_check": "PASS",
        "n_receipts": 1,
        "mode": "shadow",
    }
    att_sha = hashlib.sha256(canonicalize(att)).hexdigest()
    manifest = {
        "pack_id": "test_pack",
        "attestation": att,
        "attestation_sha256": att_sha,
        "pack_root_sha256": att_sha,
    }
    manifest.update(overrides)
    return manifest


class TestWitnessBasics:
    def test_invalid_base64(self):
        result = witness_verify("!!!not-base64!!!", "a" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("decode failed" in e for e in result.errors)

    def test_not_json(self):
        b64 = base64.b64encode(b"not json").decode()
        result = witness_verify(b64, "a" * 64)
        assert result.witness_status == "unwitnessed"

    def test_not_dict(self):
        b64 = base64.b64encode(b"[1,2,3]").decode()
        result = witness_verify(b64, "a" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("not a JSON object" in e for e in result.errors)

    def test_missing_attestation(self):
        manifest = {"pack_id": "test"}
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, "a" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("missing 'attestation'" in e for e in result.errors)


class TestHashVerification:
    def test_attestation_hash_mismatch(self):
        manifest = _make_fake_manifest()
        manifest["attestation_sha256"] = "b" * 64  # wrong hash
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, manifest["pack_root_sha256"])
        assert result.witness_status == "unwitnessed"
        assert any("attestation_sha256 mismatch" in e for e in result.errors)

    def test_d12_invariant_violation(self):
        manifest = _make_fake_manifest()
        manifest["pack_root_sha256"] = "c" * 64  # different from attestation_sha256
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, "c" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("D12 invariant" in e for e in result.errors)

    def test_submission_consistency_fail(self):
        manifest = _make_fake_manifest()
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, "d" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("submission consistency" in e for e in result.errors)

    def test_hash_verified_without_signature(self):
        manifest = _make_fake_manifest()
        root = manifest["pack_root_sha256"]
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, root)
        assert result.witness_status == "hash_verified"
        assert result.extracted["pack_root_sha256"] == root
        assert result.extracted["receipt_integrity"] == "PASS"
        assert result.extracted["n_receipts"] == 1


class TestExtractedFields:
    def test_optional_fields_omitted_when_none(self):
        from jcs import canonicalize
        att = {
            "pack_id": "minimal",
            "receipt_integrity": "PASS",
            "claim_check": "N/A",
            "n_receipts": 0,
        }
        att_sha = hashlib.sha256(canonicalize(att)).hexdigest()
        manifest = {
            "attestation": att,
            "attestation_sha256": att_sha,
            "pack_root_sha256": att_sha,
        }
        b64 = base64.b64encode(json.dumps(manifest).encode()).decode()
        result = witness_verify(b64, att_sha)
        assert "mode" not in result.extracted
        assert "timestamp_start" not in result.extracted
        assert "signer_pubkey_sha256" not in result.extracted


class TestRealCorpusPack:
    """Tests against real corpus packs (skipped if ccio not available)."""

    def test_good_pack_signature_verified(self):
        b64, root = _load_manifest_b64_and_root()
        if b64 is None:
            return  # skip if corpus not available
        try:
            from nacl.signing import VerifyKey  # noqa: F401
        except ImportError:
            return  # skip if PyNaCl not installed
        result = witness_verify(b64, root)
        assert result.witness_status == "signature_verified", f"errors: {result.errors}"
        assert result.ok
        assert result.extracted["receipt_integrity"] == "PASS"
        assert result.extracted["claim_check"] == "PASS"

    def test_wrong_root_rejected(self):
        b64, root = _load_manifest_b64_and_root()
        if b64 is None:
            return
        result = witness_verify(b64, "0" * 64)
        assert result.witness_status == "unwitnessed"
        assert any("submission consistency" in e for e in result.errors)
