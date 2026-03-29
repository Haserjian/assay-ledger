# Design: Signed Ledger Checkpoints

**Status**: Draft — not yet implemented.
**Triggered by**: Adversarial simulation (2026-03-29) — all 4 ledger chain attacks succeeded.

---

## Problem Statement

The current ledger hash chain (`prev_entry_hash`) is self-referential:
an attacker with write access to `ledger.jsonl` can recompute a valid
chain from any fabricated entry forward. There is no external anchor
that pins the chain to wall-clock time or an independent witness.

### Attacks that succeed today

| Attack | Root cause |
|--------|-----------|
| Insert into entries 1-15 (unchained zone) | First 15 entries have no `prev_entry_hash` |
| Full chain rewrite | Chain is self-referential, no external anchor |
| Mutate unchained entry fields | No integrity on pre-chain entries |
| Truncate tail entries | No sealed tip, no expected entry count |
| Append forged entry with correct prev_hash | No authorization gate on chain participation |

---

## Design Goals

1. **Genesis-to-tip chaining**: every entry, including the original 15, participates in the chain.
2. **Signed checkpoint**: a periodic signed record that anchors the chain tip externally.
3. **Truncation detection**: verifier can detect missing tail entries.
4. **Rewrite detection**: recomputing the chain from a forged entry invalidates the checkpoint.

Non-goals (this revision):
- Merkle tree / inclusion proofs (CT-style). These add value but are a later step.
- External timestamp authority integration (Rekor, RFC 3161). Already exists in witness layer — this is about the ledger itself.

---

## Proposed Design

### 1. Retroactive genesis chaining

Compute `prev_entry_hash` for entries 1-15 based on the SHA-256 of the
preceding line's raw bytes (matching the existing chaining convention).
Entry 1 uses a well-known genesis hash:

```
GENESIS_HASH = sha256("assay-ledger-genesis-v1")
```

This is a one-time migration. After migration, `validate_ledger.py`
requires `prev_entry_hash` on every entry.

### 2. Checkpoint record format

A checkpoint is a signed JSON object stored alongside the ledger
(e.g., `checkpoints/checkpoint_NNN.json`):

```json
{
  "checkpoint_version": "1.0",
  "sequence_number": 20,
  "tip_hash": "<sha256 of last ledger line>",
  "entry_count": 20,
  "checkpoint_timestamp": "2026-03-29T12:00:00Z",
  "signer_id": "<ledger maintainer key>",
  "signer_pubkey": "<ed25519 pubkey hex>",
  "signature": "<ed25519 signature of canonical checkpoint>"
}
```

**Signing scope**: JCS-canonicalized checkpoint object excluding `signature`.
**Key**: same Ed25519 keystore used for pack signing (reuse, not new key infrastructure).

### 3. Checkpoint creation

- Created after each successful merge to `main` that appends to `ledger.jsonl`.
- The CI workflow (`accept-submission.yml`) computes the checkpoint after
  the PR merges.
- Checkpoints are append-only: old checkpoints are never modified.

### 4. Verifier requirements

`validate_ledger.py` gains a `--require-checkpoint` flag:

1. Load the latest checkpoint.
2. Verify Ed25519 signature on the checkpoint.
3. Verify `entry_count` matches actual ledger line count.
4. Verify `tip_hash` matches SHA-256 of the last ledger line.
5. Verify the full chain from genesis to tip (all `prev_entry_hash` values).

Without `--require-checkpoint`: existing behavior (chain validation only).
With `--require-checkpoint`: fail if no valid signed checkpoint covers the current tip.

### 5. Handling attack vectors post-checkpoint

| Attack | Detection mechanism |
|--------|-------------------|
| Insert into unchained zone | Now impossible — all entries chained from genesis |
| Full chain rewrite | Tip hash in signed checkpoint won't match |
| Mutate entry fields | Chain hash breaks at mutation point |
| Truncate tail | `entry_count` in checkpoint disagrees with line count |
| Append forged entry | Tip hash in checkpoint disagrees; next checkpoint won't sign a chain containing the forged entry |

### 6. Trust model

The checkpoint signer key is the trust root for ledger integrity.

- The key must be managed by the ledger maintainer (not the submitter).
- Key rotation: new checkpoint includes the new pubkey; old checkpoints remain valid for their era.
- Key compromise: invalidates all checkpoints signed by that key. Recovery requires re-signing from a new key with independent verification of ledger state.

This is the same trust model as TUF root keys or CT log operator keys.
It is NOT zero-trust — it requires trusting the checkpoint signer.
The alternative (Rekor/SCT anchoring) adds external trust at the cost
of infrastructure dependency. That is a separate design track.

---

## Migration Plan

1. Compute retroactive `prev_entry_hash` for entries 1-15 (one-time PR).
2. Update `validate_ledger.py` to require `prev_entry_hash` on all entries.
3. Update `check_append_invariant.py` to verify chain from genesis.
4. Add `create_checkpoint.py` and `verify_checkpoint.py` scripts.
5. Update `accept-submission.yml` to create checkpoint after merge.
6. Add `--require-checkpoint` to `validate_ledger.py`.
7. Document the trust model in `LEDGER_APPEND_SEMANTICS.md`.

---

## Open Questions

- Should checkpoints be stored in-repo (`checkpoints/`) or out-of-band?
  In-repo is simpler but means the checkpoint is in the same trust domain
  as the ledger. Out-of-band is stronger but adds infrastructure.
- Should every entry trigger a checkpoint, or only every N entries?
  Every entry is simplest and most secure; batching reduces noise.
- Should the genesis hash be a fixed constant or derived from the repo's
  initial commit SHA? Fixed constant is simpler and doesn't tie to git.
