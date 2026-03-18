# Ledger Append Semantics

**Status**: Design note — defines the append invariant before implementation.
**Relates to**: [issue #8](https://github.com/Haserjian/assay-ledger/issues/8)

## Problem

The ledger accepts submissions via `workflow_dispatch`, which builds an entry,
appends it to `ledger.jsonl`, validates, and opens a PR. Since `f31f4cf`, each
new entry carries `prev_entry_hash` (SHA-256 of the previous JSONL line), and
the validator enforces chain continuity.

However, the current concurrency key is `pack_root_sha256` (per-submission),
not global. Two submissions can observe the same ledger tail, compute the same
`prev_entry_hash`, and open competing PRs. The validator catches this *after*
the second PR attempts to merge, but does not *prevent* it.

**Current state**: detect-and-reject at merge time.
**Desired state**: enforced merge-time freshness with reduced race window.

## Core invariant

**A ledger append is valid only if its `prev_entry_hash` equals the current
tip hash of `ledger.jsonl` on `main` at merge evaluation time. Any mismatch
is stale and must be rejected, not rebased.**

This is the constitutional rule. Everything else is implementation supporting it.

## Authoritative moment

The authoritative moment is **merge evaluation** — the point at which a
proposed append is checked against the live state of `main`.

Not:
- workflow start (too early — `main` may advance before merge)
- PR creation (too early — same reason)
- workflow write time (too early — entry is a proposal, not yet committed)

The merge-time freshness check is the primary invariant layer.

## What is serialized

Three things operate, in order:

| What | Serialized by | Purpose |
|------|---------------|---------|
| Workflow execution | Concurrency group | Reduces probability of competing proposals |
| Append proposal | Validator during workflow | Catches errors before PR creation |
| Merge permission | Required status check on PR | **Enforces freshness against live `main`** |

Only the third is the real invariant. The first two reduce pressure and improve
UX, but they are not sufficient alone.

## Merge-time freshness and shape enforcement

A required status check must run on the PR's merge candidate and verify
two properties:

### 1. Append-only diff shape

The PR must change `ledger.jsonl` by exactly one appended logical JSONL
record. No prior records may be modified, reordered, or removed.
Freshness alone is insufficient if earlier ledger content can be altered.

Implementation: compare the PR's `ledger.jsonl` against `main`'s version
byte-for-byte up to the end of the `main` content. The PR file must be
identical up to that point and contain exactly one additional non-empty
line. Comparison must be byte-level, not parsed — do not reserialize.

Terminal newline handling: the final newline after the appended record is
required (JSONL convention). The check must not be brittle to its presence
or absence in the base file.

The PR must not modify any files outside `ledger.jsonl` unless explicitly
allowed (e.g., a version counter file if one is later introduced). Append
PRs that piggyback unrelated changes must fail the merge-time check.

### 2. Chain freshness

The appended entry's `prev_entry_hash` must equal the SHA-256 of the
last line of `ledger.jsonl` on `main`:

```
entry.prev_entry_hash == SHA256(last_line(ledger.jsonl on main))
```

If either check fails, the PR cannot merge.

### Trigger and merge strategy compatibility

This check must be a **required status check** for merge into `main`.

The workflow should be triggered on `pull_request` for standard merges.
If GitHub merge queue is adopted later, the workflow must also run on
the merge group candidate (`merge_group` trigger) so the invariant
survives regardless of merge strategy.

The check must operate on the merge candidate content actually being
evaluated for merge, not on a stale earlier PR snapshot.

Implementation: a CI workflow that:
1. Checks out both `main` and the PR branch
2. Asserts `ledger.jsonl` diff is exactly one appended line
3. Computes SHA-256 of the last line on `main`
4. Reads `prev_entry_hash` from the appended entry
5. Compares — mismatch or shape violation = hard failure

## Concurrency reduction (supporting, not sufficient)

Change the concurrency group from per-submission to global:

```yaml
concurrency:
  group: ledger-append          # was: ledger-submit-${{ inputs.pack_root_sha256 }}
  cancel-in-progress: false     # queue, don't cancel — submissions are valuable
```

This reduces the race window by ensuring workflow runs don't overlap. But it
does not eliminate staleness because:
- A PR can sit open while another submission merges
- Manual edits can change `main` between workflow run and merge

Concurrency is pressure reduction, not correctness.

## Staleness rule

An entry is stale if:
```
entry.prev_entry_hash != SHA256(last_line(ledger.jsonl on main))
```

Stale entries must be **rejected**. They are not automatically rebased because:
- Rebase changes `prev_entry_hash`, altering the entry's chain relationship
- That should be an explicit re-submission, not a silent mutation
- The submitter must re-trigger the workflow against the new head

There is no queue or retry. Rejection is the honest failure mode.

## Merge model

PRs are the merge mechanism. The rules:

1. Stale PRs must be re-triggered by the submitter (not rebased by maintainers)
2. Maintainers must not override a failing freshness check
3. Merge queue is not required at current volume but is compatible with this model
4. The freshness CI check is a **required status check**, not advisory

## Defense layers (ordered by authority)

| # | Layer | Role | Authority level |
|---|-------|------|-----------------|
| 1 | **Merge-time freshness check** | Enforces invariant | **Constitutional** — blocks merge |
| 2 | **Validator in workflow** | Catches errors at proposal time | Enforcement — prevents bad PRs |
| 3 | **Global concurrency group** | Reduces race window | Operational — pressure reduction |
| 4 | **Git merge conflict** | Incidental defense from JSONL structure | Accidental — not policy |
| 5 | **Post-merge CI audit** | Confirms chain integrity after the fact | Audit — detection, not prevention |

Layers 1 and 2 are the real contract. Layers 3-5 are supporting infrastructure.

## What this does NOT guarantee

- **Cryptographic ordering**: the chain is hash-linked, not signed. A
  repository admin can rewrite history. The ledger's integrity depends on
  repository access controls, not on the chain alone.
- **Global uniqueness beyond GitHub**: the ledger is authoritative only
  within this repository. Cross-ledger deduplication is out of scope.
- **Atomic merge**: GitHub PR merge is not a single atomic operation from
  the ledger's perspective. The merge commit is the authoritative state
  transition, and post-merge CI confirms chain integrity.
- **Protection against admin override**: a maintainer with merge permissions
  can bypass required checks. This is a GitHub access-control boundary, not
  a ledger invariant.

## Implementation checklist

1. [ ] Add merge-time CI workflow: append-only shape + chain freshness
       (triggers: `pull_request` and `merge_group`, required status check)
2. [ ] Change concurrency group to `ledger-append` (global)
3. [ ] Verify `cancel-in-progress: false` (queue, don't discard)
4. [ ] Add post-merge CI audit job that runs `validate_ledger.py` on `main`
5. [ ] Configure merge-time check as required status check in branch protection
6. [ ] Update issue #8 with link to this spec
7. [ ] Test: submit two entries in quick succession, confirm second queues
8. [ ] Test: open a PR, merge a different entry first, confirm original PR
       fails freshness check and cannot merge
9. [ ] Test: PR that modifies an earlier ledger line fails shape check
10. [ ] Test: PR that modifies files besides ledger.jsonl fails scope check
