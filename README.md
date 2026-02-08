# Assay Public Ledger

Append-only public record of **cryptographically witnessed** AI evidence bundles ([Proof Packs](https://pypi.org/project/assay-ai/)).

**Live at:** [https://haserjian.github.io/assay-ledger/](https://haserjian.github.io/assay-ledger/)

## What this is

Every entry is a SHA-256 fingerprint of a verified Proof Pack attestation. The ledger records *when* a verification result was recorded and *what* the result was, without storing the evidence itself.

Entries submitted with a `pack_manifest.json` are **independently witnessed** by the ledger -- the Ed25519 signature, attestation hash chain, and D12 invariant are cryptographically verified before acceptance.

## Witness levels

| Level | Badge | What it proves |
|-------|-------|----------------|
| `signature_verified` | **SIG** | Ed25519 signature valid, attestation hash chain intact, signer key fingerprint matches |
| `hash_verified` | **HASH** | Attestation hash chain intact, but signature not checked |
| `unwitnessed` | **SELF** | Self-reported by submitter, not independently verified |

## Invariants

1. **Append-only.** Existing entries are never modified or removed. CI enforces this on every PR.
2. **Unique fingerprints.** Each `pack_root_sha256` appears at most once.
3. **Schema-validated.** Every entry is checked against `ledger.schema.json` on every push.
4. **Publicly verifiable.** Anyone with the original pack can verify it matches a ledger entry.
5. **Witnessed entries use manifest-derived fields.** When a manifest is provided, the entry fields are extracted by the witness, not the submitter.

## How to verify any entry

```bash
pip install assay-ai

# Verify a pack you received
assay verify-pack ./proof_pack_dir/

# Compare the pack_root_sha256 from pack_manifest.json
# against the ledger entry -- they should match.
python3 -c "
import json
manifest = json.load(open('./proof_pack_dir/pack_manifest.json'))
print(manifest['pack_root_sha256'])
"
```

## Submit an entry

### Option 1: Witnessed submission (recommended)

Include the full `pack_manifest.json` as base64. The ledger witness verifies it independently.

```yaml
    - name: Submit to Assay Public Ledger (witnessed)
      if: steps.verify.outputs.exit-code == '0'
      run: |
        MANIFEST="${{ steps.verify.outputs.pack-path }}/pack_manifest.json"
        gh workflow run accept-submission.yml \
          -R Haserjian/assay-ledger \
          -f pack_root_sha256=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['pack_root_sha256'])") \
          -f source_repo=${{ github.repository }} \
          -f pack_manifest_b64=$(base64 -w0 < "$MANIFEST")
      env:
        GH_TOKEN: ${{ secrets.LEDGER_TOKEN }}
```

### Option 2: Manual (PR)

```bash
python submit_entry.py ./path/to/proof_pack/ your-org/your-repo
# Then commit and open a PR
```

### Option 3: Unwitnessed submission (legacy)

Without a manifest, the entry is marked `unwitnessed` and fields are self-reported.

```yaml
    - name: Submit to Assay Public Ledger (unwitnessed)
      run: |
        gh workflow run accept-submission.yml \
          -R Haserjian/assay-ledger \
          -f pack_root_sha256="..." \
          -f source_repo=${{ github.repository }} \
          -f pack_id="..." \
          -f receipt_integrity="PASS" \
          -f claim_check="PASS" \
          -f n_receipts="5"
      env:
        GH_TOKEN: ${{ secrets.LEDGER_TOKEN }}
```

## Schema

See [`ledger.schema.json`](ledger.schema.json) for the full JSON Schema.

Required fields: `schema_version`, `pack_root_sha256`, `pack_id`, `receipt_integrity`, `claim_check`, `n_receipts`, `submitted_at`, `source_repo`.

Optional fields: `timestamp_start`, `timestamp_end`, `mode`, `assurance_level`, `source_workflow`, `signer_pubkey_sha256`, `verifier_version`, `witness_status`.

## Links

- [assay-ai on PyPI](https://pypi.org/project/assay-ai/)
- [Assay source](https://github.com/Haserjian/ccio)
- [Assay Verify Action](https://github.com/Haserjian/assay-verify-action)
