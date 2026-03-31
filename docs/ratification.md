# Checkpoint Ratification Procedure

Checkpoint publication is governed — a signed checkpoint becomes part of the
protected ledger history only after it passes CI verification and is merged
through an explicit PR. This document describes the normal path and the manual
fallback.

---

## Normal path (CHECKPOINT_PR_TOKEN configured)

1. A push to `ledger.jsonl` (or `workflow_dispatch`) triggers `checkpoint-sign.yml`.
2. The workflow emits a signed checkpoint, verifies it locally, and opens a PR
   from a `checkpoint/checkpoint_XXXX-runYYYY` branch.
3. Because the PR was opened with `CHECKPOINT_PR_TOKEN` (a PAT), GitHub fires
   `pull_request` events and the three required checks run automatically:
   - **Checkpoint Trust Gate** — verifies signature + T1 requirement on main
   - **Checkpoint Validate** — verifies signature, registry, T1, monotonicity
   - **Validate Ledger** — detects checkpoint-only PR, skips ledger invariants
4. When all three are green, merge the PR.

---

## Manual fallback (CHECKPOINT_PR_TOKEN not set)

When `CHECKPOINT_PR_TOKEN` is not configured, the PR is opened with
`GITHUB_TOKEN`. GitHub suppresses `pull_request` workflow triggers for
bot-created PRs, so the required checks do not fire automatically.

**Fallback procedure:**

```bash
# 1. Identify the checkpoint branch
gh pr list --repo Haserjian/assay-ledger --state open

# 2. Fetch and push an empty synchronize commit
git fetch origin <branch>
git checkout <branch>
git commit --allow-empty -m "ci: synchronize — trigger checkpoint-validate"
git push origin <branch>
git checkout main

# 3. Wait for checks (usually < 2 minutes)
# Watch: https://github.com/Haserjian/assay-ledger/pulls

# 4. Verify all three checks are green before merging
```

**What to look for before merging:**
- `checkpoint-trust` ✅
- `checkpoint-validate` ✅
- `validate` ✅ (will show "Checkpoint-only PR — ledger validation skipped")

**Do not merge if any check is red or missing.**

---

## Activating the normal path (removing the fallback)

1. Create a GitHub Personal Access Token with `repo` and `workflow` scopes
   (or a fine-grained token with pull-requests:write).
2. Store it as `CHECKPOINT_PR_TOKEN` in Settings → Secrets and variables → Actions.
3. Future checkpoint PRs will fire checks automatically — no synchronize push needed.

---

## What constitutes a valid ratification

A checkpoint PR is validly ratified when:
1. `checkpoint-validate` passed — cryptographic + registry + monotonicity checks
2. `checkpoint-trust` passed — latest checkpoint meets the active trust tier (T1)
3. `validate` passed — either ran cleanly or correctly skipped (checkpoint-only)
4. The merge was performed by a human reviewer, not automated

A bypass of required checks is never the routine path. Any bypass must be
documented with a governance exception receipt in `~/.claude/state/receipts/`.

---

## Trust tier state

See `trust_state.json` in the repo root for current enforcement state.
See `docs/LEDGER_TRUST_MODEL.md` for the full trust architecture.
