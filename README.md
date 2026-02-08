# Assay Public Ledger

Append-only public record of verified AI evidence bundles ([Proof Packs](https://pypi.org/project/assay-ai/)).

**Live at:** [https://haserjian.github.io/assay-ledger/](https://haserjian.github.io/assay-ledger/)

## What this is

Every entry is a SHA-256 fingerprint of a verified Proof Pack attestation. The ledger records *when* a verification result was recorded and *what* the result was, without storing the evidence itself.

```
{"schema_version":1,"pack_root_sha256":"277e19dd...","pack_id":"pack_20260207...","receipt_integrity":"PASS","claim_check":"PASS","n_receipts":2,...}
```

## Invariants

1. **Append-only.** Existing entries are never modified or removed. CI enforces this on every PR.
2. **Unique fingerprints.** Each `pack_root_sha256` appears at most once.
3. **Schema-validated.** Every entry is checked against `ledger.schema.json` on every push.
4. **Publicly verifiable.** Anyone with the original pack can verify it matches a ledger entry.

## How to verify any entry

```bash
pip install assay-ai

# Verify a pack you received
assay verify-pack ./proof_pack_dir/

# Compare the pack_root_sha256 from verify_report.json
# against the ledger entry — they should match.
python3 -c "
import json
report = json.load(open('./proof_pack_dir/pack_manifest.json'))
print(report['pack_root_sha256'])
"
```

## Submit an entry

### Option 1: Manual (PR)

```bash
python submit_entry.py ./path/to/proof_pack/ your-org/your-repo
# Then commit and open a PR
```

### Option 2: From CI (after assay verify)

Add this step after your Assay verification step:

```yaml
    - name: Submit to Assay Public Ledger
      if: steps.verify.outputs.exit-code == '0'
      run: |
        MANIFEST="${{ steps.verify.outputs.pack-path }}/pack_manifest.json"
        gh workflow run accept-submission.yml \
          -R Haserjian/assay-ledger \
          -f pack_root_sha256=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['pack_root_sha256'])") \
          -f pack_id=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['pack_id'])") \
          -f receipt_integrity=${{ steps.verify.outputs.integrity }} \
          -f claim_check=${{ steps.verify.outputs.claims }} \
          -f n_receipts=$(python3 -c "import json; m=json.load(open('$MANIFEST')); print(m['attestation']['n_receipts'])") \
          -f source_repo=${{ github.repository }}
      env:
        GH_TOKEN: ${{ secrets.LEDGER_TOKEN }}
```

## Schema

See [`ledger.schema.json`](ledger.schema.json) for the full JSON Schema.

Required fields: `schema_version`, `pack_root_sha256`, `pack_id`, `receipt_integrity`, `claim_check`, `n_receipts`, `timestamp_start`, `submitted_at`, `source_repo`.

## Links

- [assay-ai on PyPI](https://pypi.org/project/assay-ai/)
- [Assay source](https://github.com/Haserjian/ccio)
- [Assay Verify Action](https://github.com/Haserjian/assay-verify-action)
