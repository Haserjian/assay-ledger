from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from submit_entry import extract_entry


def _write_manifest(pack_dir: Path, attestation: dict) -> None:
    manifest = {
        "pack_root_sha256": "a" * 64,
        "attestation_sha256": "a" * 64,
        "attestation": attestation,
    }
    (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest))


def test_extract_entry_requires_receipt_integrity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    _write_manifest(pack_dir, {"claim_check": "N/A", "n_receipts": 0})

    with pytest.raises(SystemExit) as excinfo:
        extract_entry(pack_dir, "Haserjian/ccio")

    assert excinfo.value.code == 1
    assert "receipt_integrity" in capsys.readouterr().err


def test_extract_entry_accepts_pass_receipt_integrity(tmp_path: Path) -> None:
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    _write_manifest(
        pack_dir,
        {
            "pack_id": "pack_demo",
            "receipt_integrity": "PASS",
            "claim_check": "PASS",
            "n_receipts": 2,
        },
    )

    entry = extract_entry(pack_dir, "Haserjian/ccio")

    assert entry["receipt_integrity"] == "PASS"
    assert entry["claim_check"] == "PASS"
    assert entry["n_receipts"] == 2
    assert entry["source_repo"] == "Haserjian/ccio"
