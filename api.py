"""Optional FastAPI wrapper for the Assay public ledger.

This REST surface is deliberately small: it appends witnessed Assay proof-pack
manifests to the existing JSONL ledger and verifies entries already present in
that ledger. The PR/CI append flow remains authoritative.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException

from idempotency import parse_idempotency_key
from jcs import canonicalize
from validate_ledger import GENESIS_HASH, SHA256_RE, validate_ledger
from witness_verify import witness_verify

try:
    import fcntl
except ImportError:  # pragma: no cover - fcntl is present on macOS/Linux CI.
    fcntl = None  # type: ignore[assignment]


LEDGER_ID = "assay-ledger"
LEDGER_PATH = Path(os.environ.get("ASSAY_LEDGER_PATH", Path(__file__).with_name("ledger.jsonl")))
IDEMPOTENCY_PATH = Path(
    os.environ.get("ASSAY_LEDGER_IDEMPOTENCY_PATH", Path(__file__).with_name(".idempotency.jsonl"))
)
LOCK_PATH = Path(os.environ.get("ASSAY_LEDGER_LOCK_PATH", Path(__file__).with_name(".ledger.lock")))

app = FastAPI(title="Assay Ledger REST v1", version="1.0")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextmanager
def _ledger_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+") as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _manifest_content_hash(pack_manifest: dict[str, Any]) -> str:
    return _sha256_hex(canonicalize(pack_manifest))


def _root_from_manifest(pack_manifest: dict[str, Any]) -> str:
    root = str(pack_manifest.get("pack_root_sha256") or pack_manifest.get("attestation_sha256") or "")
    if not SHA256_RE.match(root):
        raise HTTPException(status_code=400, detail="pack_manifest must include 64-hex pack_root_sha256")
    return root


def _ledger_rows(path: Path | None = None) -> list[tuple[int, str, dict[str, Any]]]:
    ledger_path = path or LEDGER_PATH
    rows: list[tuple[int, str, dict[str, Any]]] = []
    if not ledger_path.exists():
        return rows
    index = 0
    for raw in ledger_path.read_text().splitlines():
        line = raw.strip()
        if not line:
            continue
        rows.append((index, line, json.loads(line)))
        index += 1
    return rows


def _find_by_root(root: str) -> tuple[int, str, dict[str, Any]] | None:
    for row in _ledger_rows():
        if row[2].get("pack_root_sha256") == root:
            return row
    return None


def _find_by_index(index: int) -> tuple[int, str, dict[str, Any]] | None:
    for row in _ledger_rows():
        if row[0] == index:
            return row
    return None


def _next_prev_entry_hash() -> str:
    rows = _ledger_rows()
    if not rows:
        return GENESIS_HASH
    return _sha256_hex(rows[-1][1].encode())


def _response_for_row(row: tuple[int, str, dict[str, Any]], *, duplicate: bool) -> dict[str, Any]:
    index, line, entry = row
    return {
        "ledger_id": LEDGER_ID,
        "index": index,
        "pack_root_sha256": entry["pack_root_sha256"],
        "receipt_hash": _sha256_hex(line.encode()),
        "duplicate": duplicate,
    }


def _load_idempotency() -> dict[str, dict[str, Any]]:
    if not IDEMPOTENCY_PATH.exists():
        return {}
    records: dict[str, dict[str, Any]] = {}
    for raw in IDEMPOTENCY_PATH.read_text().splitlines():
        if not raw.strip():
            continue
        record = json.loads(raw)
        records[str(record["idempotency_key"])] = record
    return records


def _remember_idempotency(idempotency_key: str, content_hash: str, root: str, index: int) -> None:
    IDEMPOTENCY_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "idempotency_key": idempotency_key,
        "content_hash": content_hash,
        "pack_root_sha256": root,
        "ledger_id": LEDGER_ID,
        "index": index,
    }
    with IDEMPOTENCY_PATH.open("a") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


def _extract_entry(pack_manifest: dict[str, Any], source_repo: str) -> dict[str, Any]:
    root = _root_from_manifest(pack_manifest)
    manifest_bytes = json.dumps(pack_manifest, sort_keys=True, separators=(",", ":")).encode()
    result = witness_verify(base64.b64encode(manifest_bytes).decode(), root)
    if not result.ok:
        raise HTTPException(status_code=400, detail={"witness_errors": result.errors})

    extracted = result.extracted
    receipt_integrity = extracted.get("receipt_integrity")
    if receipt_integrity not in {"PASS", "FAIL"}:
        raise HTTPException(
            status_code=400,
            detail="pack_manifest attestation.receipt_integrity must be PASS or FAIL",
        )

    entry: dict[str, Any] = {
        "schema_version": 1,
        "pack_root_sha256": root,
        "pack_id": extracted.get("pack_id", pack_manifest.get("pack_id", "")),
        "receipt_integrity": receipt_integrity,
        "claim_check": extracted.get("claim_check", "N/A"),
        "n_receipts": extracted.get("n_receipts", 0),
        "submitted_at": _utc_now(),
        "source_repo": source_repo,
        "witness_status": result.witness_status,
    }

    for key in (
        "mode",
        "assurance_level",
        "timestamp_start",
        "timestamp_end",
        "signer_pubkey_sha256",
        "verifier_version",
    ):
        value = extracted.get(key)
        if value:
            entry[key] = value
    return entry


def _append_validated_entry(entry: dict[str, Any]) -> tuple[int, str, dict[str, Any]]:
    entry["prev_entry_hash"] = _next_prev_entry_hash()
    line = json.dumps(entry, separators=(",", ":"))
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

    existing = LEDGER_PATH.read_text() if LEDGER_PATH.exists() else ""
    candidate = LEDGER_PATH.with_suffix(LEDGER_PATH.suffix + ".candidate")
    try:
        candidate.write_text(existing + ("" if existing.endswith("\n") or not existing else "\n") + line + "\n")
        errors = validate_ledger(candidate)
        if errors:
            raise HTTPException(status_code=400, detail={"ledger_validation_errors": errors})

        with LEDGER_PATH.open("a") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(line + "\n")
    finally:
        candidate.unlink(missing_ok=True)

    row = _find_by_root(entry["pack_root_sha256"])
    if row is None:
        raise HTTPException(status_code=500, detail="ledger append did not produce a readable entry")
    return row


@app.post("/v1/ledger/append")
def append_ledger_entry(
    payload: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    source_repo = payload.get("source_repo")
    pack_manifest = payload.get("pack_manifest")
    if not isinstance(source_repo, str) or "/" not in source_repo:
        raise HTTPException(status_code=400, detail="source_repo must be owner/repo")
    if not isinstance(pack_manifest, dict):
        raise HTTPException(status_code=400, detail="pack_manifest must be a JSON object")

    root = _root_from_manifest(pack_manifest)
    content_hash = _manifest_content_hash(pack_manifest)

    with _ledger_lock():
        normalized_idempotency = ""
        if idempotency_key:
            try:
                normalized_idempotency = parse_idempotency_key(idempotency_key).raw
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            existing_idem = _load_idempotency().get(normalized_idempotency)
            if existing_idem:
                if existing_idem.get("content_hash") != content_hash:
                    raise HTTPException(
                        status_code=409,
                        detail="Idempotency-Key already used with different pack_manifest content",
                    )
                row = _find_by_root(str(existing_idem["pack_root_sha256"]))
                if row:
                    return _response_for_row(row, duplicate=True)

        existing = _find_by_root(root)
        if existing:
            response = _response_for_row(existing, duplicate=True)
            if normalized_idempotency:
                _remember_idempotency(normalized_idempotency, content_hash, root, response["index"])
            return response

        entry = _extract_entry(pack_manifest, source_repo)
        row = _append_validated_entry(entry)
        response = _response_for_row(row, duplicate=False)
        if normalized_idempotency:
            _remember_idempotency(normalized_idempotency, content_hash, root, response["index"])
        return response


@app.post("/v1/ledger/verify")
def verify_ledger_entry(payload: dict[str, Any]) -> dict[str, Any]:
    errors = validate_ledger(LEDGER_PATH)
    if errors:
        return {"valid": False, "reason": "ledger validation failed: " + "; ".join(errors[:3])}

    row: tuple[int, str, dict[str, Any]] | None = None
    root = payload.get("pack_root_sha256")
    if isinstance(root, str):
        if not SHA256_RE.match(root):
            raise HTTPException(status_code=400, detail="pack_root_sha256 must be 64 lowercase hex characters")
        row = _find_by_root(root)
    elif "ledger_id" in payload or "index" in payload:
        if payload.get("ledger_id") != LEDGER_ID:
            return {"valid": False, "reason": "unknown ledger_id"}
        index = payload.get("index")
        if not isinstance(index, int) or index < 0:
            raise HTTPException(status_code=400, detail="index must be a non-negative integer")
        row = _find_by_index(index)
    else:
        raise HTTPException(status_code=400, detail="provide pack_root_sha256 or {ledger_id,index}")

    if row is None:
        return {"valid": False, "reason": "ledger entry not found"}

    response = _response_for_row(row, duplicate=True)
    response["valid"] = True
    response.pop("duplicate", None)
    return response
