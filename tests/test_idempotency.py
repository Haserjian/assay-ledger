from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import api
from idempotency import parse_idempotency_key
from jcs import canonicalize


def _manifest(pack_id: str) -> dict:
    attestation = {
        "pack_id": pack_id,
        "receipt_integrity": "PASS",
        "claim_check": "PASS",
        "n_receipts": 1,
    }
    root = hashlib.sha256(canonicalize(attestation)).hexdigest()
    return {
        "pack_id": pack_id,
        "attestation": attestation,
        "attestation_sha256": root,
        "pack_root_sha256": root,
    }


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(api, "LEDGER_PATH", tmp_path / "ledger.jsonl")
    monkeypatch.setattr(api, "IDEMPOTENCY_PATH", tmp_path / "idempotency.jsonl")
    monkeypatch.setattr(api, "LOCK_PATH", tmp_path / "ledger.lock")
    return TestClient(api.app)


def test_parse_idempotency_key_normalizes_hashes() -> None:
    key = parse_idempotency_key("Haserjian:assay:" + "A" * 40 + ":" + "B" * 64)
    assert key.owner == "Haserjian"
    assert key.repo == "assay"
    assert key.commit_sha == "a" * 40
    assert key.action_hash == "b" * 64


@pytest.mark.parametrize(
    "bad_key",
    [
        "owner:repo:short:" + "b" * 64,
        "owner:repo:" + "a" * 40 + ":short",
        "owner:repo:" + "a" * 40,
        "owner/repo:" + "a" * 40 + ":" + "b" * 64,
    ],
)
def test_parse_idempotency_key_rejects_bad_shapes(bad_key: str) -> None:
    with pytest.raises(ValueError):
        parse_idempotency_key(bad_key)


def test_repeat_idempotent_append_returns_same_index(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    key = "Haserjian:assay:" + "a" * 40 + ":" + "b" * 64
    payload = {"source_repo": "Haserjian/assay", "pack_manifest": _manifest("same")}

    first = client.post("/v1/ledger/append", headers={"Idempotency-Key": key}, json=payload)
    second = client.post("/v1/ledger/append", headers={"Idempotency-Key": key}, json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["duplicate"] is True
    assert second.json()["index"] == first.json()["index"]
    assert len([line for line in api.LEDGER_PATH.read_text().splitlines() if line.strip()]) == 1


def test_same_idempotency_key_with_different_content_returns_409(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    key = "Haserjian:assay:" + "a" * 40 + ":" + "b" * 64

    first = client.post(
        "/v1/ledger/append",
        headers={"Idempotency-Key": key},
        json={"source_repo": "Haserjian/assay", "pack_manifest": _manifest("first")},
    )
    conflict = client.post(
        "/v1/ledger/append",
        headers={"Idempotency-Key": key},
        json={"source_repo": "Haserjian/assay", "pack_manifest": _manifest("second")},
    )

    assert first.status_code == 200, first.text
    assert conflict.status_code == 409
    assert "different pack_manifest" in conflict.json()["detail"]
    assert len([line for line in api.LEDGER_PATH.read_text().splitlines() if line.strip()]) == 1
