# Contributing to the Assay Public Ledger

## Submitting a Ledger Entry

### What belongs in the ledger

Each entry is a SHA-256 attestation pointer to a verified Proof Pack. The ledger does not store packs or evidence -- only fingerprints and metadata.

### How to submit

1. **Via CI** -- Trigger the `accept-submission` workflow from your repo's CI after a successful `assay verify-pack`. See README for the workflow_dispatch snippet.

2. **Via PR** -- Run `python submit_entry.py <pack_dir> <source_repo>`, commit `ledger.jsonl`, and open a PR.

### Submission rules

- Entries are **append-only**. Existing entries must not be modified or removed.
- Each `pack_root_sha256` must be unique.
- All required fields must be present and valid.
- Optional fields must be omitted (not empty strings) when not applicable.

### What the CI checks

- Schema validation (`validate_ledger.py`)
- Append-only enforcement (PR prefix must match base branch)
- Unique fingerprints

## Reporting Issues

- Bugs: open an issue
- Security: see [SECURITY.md](SECURITY.md)

## Code Changes

PRs to validation logic, workflows, or the static site are welcome. Please include a clear description of what changed and why.
