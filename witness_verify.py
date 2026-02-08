#!/usr/bin/env python3
"""L2 Witness Verifier for the Assay Public Ledger.

Performs independent cryptographic verification of a Proof Pack manifest
without requiring the full pack or the assay-ai package.

Verification steps (L2 = signature-witnessed):
  1. Decode base64 manifest → JSON dict
  2. Extract attestation, compute SHA256(JCS(attestation))
  3. Check == manifest.attestation_sha256 (attestation integrity)
  4. Check == manifest.pack_root_sha256 (D12 invariant)
  5. Check == submitted pack_root_sha256 (submission consistency)
  6. Strip {signature, pack_root_sha256} → unsigned manifest
  7. JCS-canonicalize unsigned manifest
  8. Decode manifest.signer_pubkey (base64) → Ed25519 public key
  9. Ed25519_verify(canonical_bytes, signature_bytes, pubkey)
  10. Check SHA256(pubkey_bytes) == manifest.signer_pubkey_sha256
  11. Cross-check submitted fields against manifest fields

Dependencies: PyNaCl (for Ed25519), jcs.py (vendored, zero deps)

Usage:
    python witness_verify.py <manifest_b64> <submitted_pack_root_sha256>
    python witness_verify.py --json <manifest_b64> <submitted_pack_root_sha256>
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field

from jcs import canonicalize

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


@dataclass
class WitnessResult:
    """Result of witness verification."""
    witness_status: str  # "unwitnessed" | "hash_verified" | "signature_verified"
    errors: list[str] = field(default_factory=list)
    extracted: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def witness_verify(manifest_b64: str, submitted_root: str) -> WitnessResult:
    """Perform L2 witness verification on a base64-encoded pack manifest.

    Returns a WitnessResult with witness_status and any errors.
    If verification passes, extracted fields are populated from the manifest
    (these are the canonical values that should appear in the ledger entry).
    """
    errors: list[str] = []
    extracted: dict = {}

    # 1. Decode manifest
    try:
        manifest_bytes = base64.b64decode(manifest_b64)
        manifest = json.loads(manifest_bytes)
    except Exception as e:
        return WitnessResult(
            witness_status="unwitnessed",
            errors=[f"manifest decode failed: {e}"],
        )

    if not isinstance(manifest, dict):
        return WitnessResult(
            witness_status="unwitnessed",
            errors=["manifest is not a JSON object"],
        )

    # 2. Extract attestation and compute SHA256(JCS(attestation))
    attestation = manifest.get("attestation")
    if not isinstance(attestation, dict):
        return WitnessResult(
            witness_status="unwitnessed",
            errors=["manifest missing 'attestation' object"],
        )

    attestation_canonical = canonicalize(attestation)
    computed_attestation_sha256 = _sha256_hex(attestation_canonical)

    # 3. Check == manifest.attestation_sha256
    manifest_att_sha = manifest.get("attestation_sha256", "")
    if computed_attestation_sha256 != manifest_att_sha:
        errors.append(
            f"attestation_sha256 mismatch: computed {computed_attestation_sha256[:16]}... "
            f"!= manifest {manifest_att_sha[:16]}..."
        )

    # 4. Check == manifest.pack_root_sha256 (D12 invariant)
    manifest_root = manifest.get("pack_root_sha256", "")
    if manifest_att_sha and manifest_root and manifest_att_sha != manifest_root:
        errors.append(
            f"D12 invariant violated: attestation_sha256 ({manifest_att_sha[:16]}...) "
            f"!= pack_root_sha256 ({manifest_root[:16]}...)"
        )

    # 5. Check == submitted pack_root_sha256
    if manifest_root != submitted_root:
        errors.append(
            f"submission consistency: manifest pack_root_sha256 ({manifest_root[:16]}...) "
            f"!= submitted ({submitted_root[:16]}...)"
        )

    if errors:
        return WitnessResult(
            witness_status="unwitnessed",
            errors=errors,
        )

    # Hash chain is intact. At minimum we're hash_verified.
    # Extract canonical fields from the signed manifest.
    extracted = {
        "pack_root_sha256": manifest_root,
        "pack_id": attestation.get("pack_id", manifest.get("pack_id", "")),
        "receipt_integrity": attestation.get("receipt_integrity", "UNKNOWN"),
        "claim_check": attestation.get("claim_check", "N/A"),
        "n_receipts": attestation.get("n_receipts", 0),
        "mode": attestation.get("mode"),
        "assurance_level": attestation.get("assurance_level"),
        "timestamp_start": attestation.get("timestamp_start"),
        "timestamp_end": attestation.get("timestamp_end"),
        "signer_pubkey_sha256": manifest.get("signer_pubkey_sha256"),
        "verifier_version": attestation.get("verifier_version"),
    }
    # Remove None values
    extracted = {k: v for k, v in extracted.items() if v is not None}

    # 6-7. Reconstruct unsigned manifest and JCS-canonicalize
    unsigned = {
        k: v for k, v in manifest.items()
        if k not in ("signature", "pack_root_sha256")
    }
    canonical_bytes = canonicalize(unsigned)

    # 8. Decode signer public key
    signer_pubkey_b64 = manifest.get("signer_pubkey")
    signature_b64 = manifest.get("signature")

    if not signer_pubkey_b64 or not signature_b64:
        # No signature material: we can only do hash verification
        return WitnessResult(
            witness_status="hash_verified",
            extracted=extracted,
        )

    if not NACL_AVAILABLE:
        # PyNaCl not installed: can't do signature verification
        return WitnessResult(
            witness_status="hash_verified",
            errors=["PyNaCl not available; signature verification skipped"],
            extracted=extracted,
        )

    try:
        pubkey_bytes = base64.b64decode(signer_pubkey_b64)
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        return WitnessResult(
            witness_status="hash_verified",
            errors=[f"base64 decode failed for key/signature: {e}"],
            extracted=extracted,
        )

    # 9. Ed25519 verify
    try:
        vk = VerifyKey(pubkey_bytes)
        vk.verify(canonical_bytes, signature_bytes)
    except BadSignatureError:
        return WitnessResult(
            witness_status="unwitnessed",
            errors=["Ed25519 signature verification FAILED"],
            extracted=extracted,
        )
    except Exception as e:
        return WitnessResult(
            witness_status="unwitnessed",
            errors=[f"Ed25519 verification error: {e}"],
            extracted=extracted,
        )

    # 10. Check SHA256(pubkey_bytes) == signer_pubkey_sha256
    signer_sha_manifest = manifest.get("signer_pubkey_sha256", "")
    computed_signer_sha = _sha256_hex(pubkey_bytes)
    if signer_sha_manifest and computed_signer_sha != signer_sha_manifest:
        return WitnessResult(
            witness_status="unwitnessed",
            errors=[
                f"signer_pubkey_sha256 mismatch: computed {computed_signer_sha[:16]}... "
                f"!= manifest {signer_sha_manifest[:16]}..."
            ],
            extracted=extracted,
        )

    # All checks passed: signature verified
    return WitnessResult(
        witness_status="signature_verified",
        extracted=extracted,
    )


def main() -> int:
    output_json = "--json" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--json"]

    if len(args) != 2:
        print("Usage: python witness_verify.py [--json] <manifest_b64> <submitted_pack_root_sha256>",
              file=sys.stderr)
        return 1

    manifest_b64, submitted_root = args
    result = witness_verify(manifest_b64, submitted_root)

    if output_json:
        print(json.dumps({
            "witness_status": result.witness_status,
            "ok": result.ok,
            "errors": result.errors,
            "extracted": result.extracted,
        }, indent=2))
    else:
        status_icon = {
            "signature_verified": "PASS",
            "hash_verified": "PARTIAL",
            "unwitnessed": "FAIL",
        }.get(result.witness_status, "UNKNOWN")
        print(f"Witness: {status_icon} ({result.witness_status})")
        if result.errors:
            for e in result.errors:
                print(f"  ERROR: {e}")
        if result.extracted:
            print(f"  pack_id: {result.extracted.get('pack_id', '?')}")
            print(f"  integrity: {result.extracted.get('receipt_integrity', '?')}")
            print(f"  claims: {result.extracted.get('claim_check', '?')}")
            print(f"  receipts: {result.extracted.get('n_receipts', '?')}")

    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
