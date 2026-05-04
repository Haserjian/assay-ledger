from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import api
from jcs import canonicalize
from validate_ledger import validate_ledger


def _manifest(pack_id: str = "test_pack", *, claim_check: str = "PASS") -> dict:
    attestation = {
        "pack_id": pack_id,
        "receipt_integrity": "PASS",
        "claim_check": claim_check,
        "n_receipts": 1,
        "mode": "shadow",
        "assurance_level": "L0",
        "timestamp_start": "2026-05-04T00:00:00Z",
        "timestamp_end": "2026-05-04T00:00:01Z",
        "verifier_version": "1.17.0",
    }
    root = hashlib.sha256(canonicalize(attestation)).hexdigest()
    return {
        "pack_id": pack_id,
        "attestation": attestation,
        "attestation_sha256": root,
        "pack_root_sha256": root,
        "signer_pubkey_sha256": "b" * 64,
    }


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(api, "LEDGER_PATH", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(api, "IDEMPOTENCY_PATH", tmp_path / "idempotency.jsonl")
    monkeypatch.setattr(api, "LOCK_PATH", tmp_path / "ledger.lock")
    return TestClient(api.app)


def test_append_then_verify_by_root_and_index(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    manifest = _manifest()

    appended = client.post(
        "/v1/ledger/append",
        json={"source_repo": "Haserjian/assay", "pack_manifest": manifest},
    )
    assert appended.status_code == 200, appended.text
    body = appended.json()
    assert body["ledger_id"] == "assay-ledger"
    assert body["index"] == 0
    assert body["pack_root_sha256"] == manifest["pack_root_sha256"]
    assert body["duplicate"] is False

    by_root = client.post("/v1/ledger/verify", json={"pack_root_sha256": manifest["pack_root_sha256"]})
    assert by_root.status_code == 200
    assert by_root.json()["valid"] is True
    assert by_root.json()["receipt_hash"] == body["receipt_hash"]

    by_index = client.post("/v1/ledger/verify", json={"ledger_id": "assay-ledger", "index": 0})
    assert by_index.status_code == 200
    assert by_index.json()["valid"] is True
    assert by_index.json()["pack_root_sha256"] == manifest["pack_root_sha256"]


def test_duplicate_pack_root_returns_existing_location(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = {"source_repo": "Haserjian/assay", "pack_manifest": _manifest()}

    first = client.post("/v1/ledger/append", json=payload).json()
    second = client.post("/v1/ledger/append", json=payload).json()

    assert second["duplicate"] is True
    assert (second["ledger_id"], second["index"], second["receipt_hash"]) == (
        first["ledger_id"],
        first["index"],
        first["receipt_hash"],
    )
    assert len([line for line in api.LEDGER_PATH.read_text().splitlines() if line.strip()]) == 1


def test_two_sequential_appends_preserve_valid_chain(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)

    first = client.post(
        "/v1/ledger/append",
        json={"source_repo": "Haserjian/assay", "pack_manifest": _manifest("first")},
    )
    second = client.post(
        "/v1/ledger/append",
        json={"source_repo": "Haserjian/assay", "pack_manifest": _manifest("second")},
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["index"] == 1
    assert validate_ledger(api.LEDGER_PATH) == []
