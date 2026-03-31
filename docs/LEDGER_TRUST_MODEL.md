# Ledger Trust Model

The assay-ledger uses a layered trust model for signed checkpoints.
Each tier adds a distinct, verifiable property. Higher tiers do not replace lower ones — they stack.

---

## Trust tiers

### T0 — Local self-generated key

**What it proves:**
The ledger was not modified after the checkpoint was signed.
Any tampering with the ledger (entry deletion, rewrite, truncation) will be detected by `verify_checkpoint.py`.

**What it does not prove:**
Who signed the checkpoint. Any actor with access to the local seed file (`~/.assay/keys/assay-local.key`) could have produced the signature. A compromised or shared workstation invalidates T0 without any detectable evidence.

**When it is sufficient:**
During bootstrapping, local development, and early validation. T0 is the minimum bar for any checkpoint.
T0 checkpoints are accepted by default in CI (Stage 1 of the ratchet).

---

### T1 — CI-bound key (GitHub Actions)

**What it adds:**
The signature was produced inside a named GitHub Actions workflow, using a key stored in `LEDGER_SIGNING_KEY` (a GitHub Actions Secret). T1 proves both integrity (same as T0) and CI origin. A local actor without access to the Actions Secret cannot produce a T1 checkpoint.

**What it does not prove:**
The ledger entries themselves are correct, authorized, or complete. T1 is a property of the signing process, not of the ledger content. A T1 checkpoint on a ledger with fabricated entries is still a valid T1 checkpoint.

**When it is required:**
T1 is the target for production use. Once a T1 entry is in `signers.json`, add `--require-t1` to the CI trust gate step in `.github/workflows/checkpoint-trust.yml`.

---

## Trusted signer registry (`signers.json`)

All authorized signing identities are declared in `signers.json`. Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `signer_id` | yes | Matches `signer_id` field in checkpoint JSON |
| `pubkey_sha256` | yes | SHA-256 of the raw Ed25519 public key bytes (32 bytes) |
| `trust_tier` | yes | `T0` or `T1` |
| `status` | yes | `active` or `revoked` |
| `valid_from` | yes | ISO date (YYYY-MM-DD) |
| `valid_until` | no | ISO date or null |
| `notes` | no | Human-readable context |

Registry changes must be committed to `main` and reviewed. A checkpoint signed by an unregistered signer is rejected even if the Ed25519 signature itself is valid.

---

## Enforcement ratchet

The CI trust gate (`checkpoint-trust.yml`) has two stages:

| Stage | Condition | Behavior |
|-------|-----------|----------|
| 1 (current) | No T1 entry in `signers.json` | Accept T0-active signers; reject unregistered |
| 2 (target) | T1 entry added; `--require-t1` uncommented | Reject T0 signers; require T1 or higher |

**Do not add `--require-t1` before a T1 signer entry exists in `signers.json`.** The CI job will fail on the first verification attempt if you do.

---

## Promoting to T1

1. Generate a new Ed25519 key pair:
   ```
   python3 -c "
   from nacl.signing import SigningKey; import base64, hashlib
   sk = SigningKey.generate()
   seed = sk.encode()
   pubkey = sk.verify_key.encode()
   print('seed (store in LEDGER_SIGNING_KEY):', base64.b64encode(seed).decode())
   print('pubkey_sha256:', hashlib.sha256(pubkey).hexdigest())
   print('signer_pubkey:', base64.b64encode(pubkey).decode())
   "
   ```

2. Store the base64-encoded seed as `LEDGER_SIGNING_KEY` in GitHub Actions Secrets
   (Settings → Secrets and variables → Actions).

3. Add a T1 entry to `signers.json`:
   ```json
   {
     "signer_id": "assay-ci",
     "pubkey_sha256": "<output from step 1>",
     "trust_tier": "T1",
     "status": "active",
     "valid_from": "<today>",
     "valid_until": null,
     "notes": "GitHub Actions CI key — workflow: checkpoint-sign.yml"
   }
   ```

4. Commit the `signers.json` change to `main`.

5. Uncomment `--require-t1` in `.github/workflows/checkpoint-trust.yml`.

6. CI will now reject any checkpoint not signed by the registered T1 identity.

---

## Key revocation

To revoke a signing key:
1. Change its `status` to `revoked` in `signers.json`.
2. Set `valid_until` to the revocation date.
3. Commit and merge to `main`.
4. Generate a new key and add a new entry before the next checkpoint.

CI will reject any checkpoint signed by a revoked key.
