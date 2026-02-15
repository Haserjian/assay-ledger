# Repo Charter: assay-ledger

## Purpose

Append-only public transparency ledger for cryptographically witnessed
Proof Pack attestations. Provides independent, third-party evidence
anchoring (Trust Tier 2).

## Trust Boundary

**Public.** Ledger entries are public records. The witness verifies
Ed25519 signatures and attestation hash chains before accepting entries.
No secrets are stored in entries. The witness signing key is held by CI.

## What Lives Here

- `ledger.json` -- append-only record of witnessed attestations
- `ledger.schema.json` -- JSON Schema for entry validation
- `submit_entry.py` -- submission helper script
- `.github/workflows/` -- CI: schema validation, append-only enforcement, witness verification
- GitHub Pages deployment (live at `haserjian.github.io/assay-ledger`)

## What Does Not Live Here

- The Assay CLI or SDK (see `assay`)
- Proof Pack contents (ledger stores fingerprints only)
- CI verification action (see `assay-verify-action`)

## Versioning Contract

- `schema_version` field in `ledger.json` entries
- Schema changes that add optional fields are non-breaking
- Schema changes that add required fields or change semantics require a version bump
- Append-only invariant: existing entries are never modified or removed

## Consumer Workflow

```bash
# Verify a pack you received
assay verify-pack ./proof_pack_dir/

# Check the pack's fingerprint against the ledger
python3 -c "
import json
manifest = json.load(open('./proof_pack_dir/pack_manifest.json'))
print(manifest['pack_root_sha256'])
"
# Compare with ledger entry at haserjian.github.io/assay-ledger
```

## Related Repos

| Repo | Role |
|------|------|
| [assay](https://github.com/Haserjian/assay) | Core CLI + SDK (canonical source) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
