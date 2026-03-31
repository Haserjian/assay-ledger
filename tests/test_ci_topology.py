"""CI topology regression tests.

Validates the governance-layer invariants that are encoded in workflow files
and trust_state.json. Catches accidental regressions to workflow triggers,
scope detection, and trust enforcement config — before a bad push makes it
to CI.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


# ── helpers ──────────────────────────────────────────────────────────────────

def _read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text()


def _trust_state() -> dict:
    return json.loads((ROOT / "trust_state.json").read_text())


# ── validate.yml topology ─────────────────────────────────────────────────────

class TestValidateWorkflowTopology:
    def test_validate_triggers_on_pull_request(self):
        """validate.yml must trigger on pull_request to serve as a required check."""
        content = _read_workflow("validate.yml")
        assert "pull_request:" in content

    def test_validate_has_no_paths_ignore_checkpoints(self):
        """paths-ignore: checkpoints/** prevents the workflow from running, breaking
        required-check enforcement. Scope detection must be done inside the job."""
        content = _read_workflow("validate.yml")
        assert "paths-ignore" not in content, (
            "validate.yml must not use paths-ignore — use in-job scope detection instead. "
            "paths-ignore prevents the check from running, which leaves required checks pending."
        )

    def test_validate_has_scope_detection_step(self):
        """validate.yml must detect checkpoint-only PRs and skip ledger steps."""
        content = _read_workflow("validate.yml")
        assert "checkpoint_only" in content
        assert "Detect PR scope" in content

    def test_validate_ledger_steps_are_conditional(self):
        """Substantive ledger steps must be guarded by checkpoint_only != 'true'."""
        content = _read_workflow("validate.yml")
        assert "steps.scope.outputs.checkpoint_only != 'true'" in content

    def test_append_invariant_step_is_conditional(self):
        """The append invariant check must not run on checkpoint-only PRs."""
        content = _read_workflow("validate.yml")
        # The append invariant step must have both the scope guard and event check
        assert "checkpoint_only != 'true'" in content
        assert "check_append_invariant.py" in content


# ── checkpoint-validate.yml topology ─────────────────────────────────────────

class TestCheckpointValidateTopology:
    def test_checkpoint_validate_triggers_on_pull_request(self):
        content = _read_workflow("checkpoint-validate.yml")
        assert "pull_request:" in content

    def test_checkpoint_validate_scoped_to_checkpoints_path(self):
        """checkpoint-validate must only run on PRs touching checkpoints/**."""
        content = _read_workflow("checkpoint-validate.yml")
        assert "checkpoints/**" in content
        assert "paths:" in content

    def test_checkpoint_validate_requires_t1(self):
        """checkpoint-validate must enforce T1 on publication PRs."""
        content = _read_workflow("checkpoint-validate.yml")
        assert "--require-t1" in content

    def test_checkpoint_validate_checks_monotonicity(self):
        """checkpoint-validate must verify sequence_number is contiguous."""
        content = _read_workflow("checkpoint-validate.yml")
        assert "monoton" in content.lower() or "sequence_number" in content

    def test_checkpoint_validate_uses_registry(self):
        """checkpoint-validate must check signer registry membership."""
        content = _read_workflow("checkpoint-validate.yml")
        assert "--registry signers.json" in content


# ── checkpoint-trust.yml topology ────────────────────────────────────────────

class TestCheckpointTrustTopology:
    def test_trust_gate_triggers_on_pull_request(self):
        content = _read_workflow("checkpoint-trust.yml")
        assert "pull_request:" in content

    def test_trust_gate_triggers_on_push_to_main(self):
        content = _read_workflow("checkpoint-trust.yml")
        assert "push:" in content
        assert "main" in content

    def test_t1_enforcement_is_active(self):
        """Stage 2 must be active: --require-t1 must be uncommented."""
        content = _read_workflow("checkpoint-trust.yml")
        # The --require-t1 line must not be commented out
        active_lines = [
            line for line in content.splitlines()
            if "--require-t1" in line and not line.strip().startswith("#")
        ]
        assert active_lines, (
            "--require-t1 is commented out in checkpoint-trust.yml. "
            "Stage 2 enforcement is not active."
        )

    def test_t1_enforcement_not_using_stage1_fallback(self):
        """The old Stage 1 line (without --require-t1) must not be the active call."""
        content = _read_workflow("checkpoint-trust.yml")
        # No active (uncommented) verify call without --require-t1
        for line in content.splitlines():
            stripped = line.strip()
            if (stripped.startswith("python verify_checkpoint.py") and
                    "--require-t1" not in stripped and
                    not stripped.startswith("#")):
                raise AssertionError(
                    f"Found active verify_checkpoint.py call without --require-t1: {line!r}. "
                    "Stage 2 should be the only active verification."
                )


# ── checkpoint-sign.yml topology ─────────────────────────────────────────────

class TestCheckpointSignTopology:
    def test_pr_creation_uses_pat_fallback_pattern(self):
        """checkpoint-sign.yml should attempt CHECKPOINT_PR_TOKEN before GITHUB_TOKEN."""
        content = _read_workflow("checkpoint-sign.yml")
        assert "CHECKPOINT_PR_TOKEN" in content, (
            "checkpoint-sign.yml should use CHECKPOINT_PR_TOKEN for PR creation. "
            "GITHUB_TOKEN-created PRs do not fire pull_request workflow triggers."
        )

    def test_sign_workflow_has_three_phases(self):
        """checkpoint-sign.yml must maintain emit/verify/publish separation."""
        content = _read_workflow("checkpoint-sign.yml")
        assert "Phase 1" in content or "Emit" in content
        assert "Phase 2" in content or "Verify" in content
        assert "Phase 3" in content or "Publish" in content

    def test_branch_name_includes_run_id(self):
        """Branch name must include run_id to prevent retry collisions."""
        content = _read_workflow("checkpoint-sign.yml")
        assert "github.run_id" in content


# ── trust_state.json ──────────────────────────────────────────────────────────

class TestTrustState:
    def test_trust_state_exists(self):
        assert (ROOT / "trust_state.json").exists()

    def test_trust_stage_is_2(self):
        state = _trust_state()
        assert state["trust_stage"] == 2, (
            f"Expected trust_stage=2 (T1 enforced), got {state['trust_stage']}"
        )

    def test_require_t1_is_true(self):
        state = _trust_state()
        assert state["require_t1"] is True

    def test_minimum_trust_tier_is_t1(self):
        state = _trust_state()
        assert state["minimum_trust_tier"] == "T1"

    def test_active_signer_is_t1(self):
        state = _trust_state()
        assert state["active_signer"]["trust_tier"] == "T1"

    def test_latest_checkpoint_is_t1(self):
        state = _trust_state()
        assert state["latest_checkpoint"]["trust_tier"] == "T1"

    def test_latest_checkpoint_file_exists(self):
        state = _trust_state()
        cp_file = ROOT / state["latest_checkpoint"]["file"]
        assert cp_file.exists(), f"Latest checkpoint file {cp_file} not found on disk"


# ── trust_state.json cross-validation (drift detection) ──────────────────────

class TestTrustStateCrossValidation:
    """Verify trust_state.json agrees with the authoritative sources it summarizes.

    trust_state.json is a derived state artifact, not a constitutional source.
    These tests catch drift between the summary and the real sources:
    signers.json, checkpoint files, and the active workflow config.
    """

    def test_active_signer_exists_in_registry(self):
        """trust_state.active_signer.signer_id must be in signers.json."""
        state = _trust_state()
        registry = json.loads((ROOT / "signers.json").read_text())
        signer_ids = {s["signer_id"] for s in registry["signers"]}
        claimed_id = state["active_signer"]["signer_id"]
        assert claimed_id in signer_ids, (
            f"trust_state.json claims active signer {claimed_id!r} "
            f"but signers.json has: {signer_ids}"
        )

    def test_active_signer_tier_matches_registry(self):
        """trust_state.active_signer.trust_tier must match signers.json."""
        state = _trust_state()
        registry = json.loads((ROOT / "signers.json").read_text())
        signers = {s["signer_id"]: s for s in registry["signers"]}
        claimed_id = state["active_signer"]["signer_id"]
        claimed_tier = state["active_signer"]["trust_tier"]
        registry_tier = signers[claimed_id]["trust_tier"]
        assert claimed_tier == registry_tier, (
            f"trust_state.json says tier={claimed_tier!r} for {claimed_id!r}, "
            f"but signers.json says {registry_tier!r}"
        )

    def test_active_signer_is_active_in_registry(self):
        """trust_state.active_signer must have status=active in signers.json."""
        state = _trust_state()
        registry = json.loads((ROOT / "signers.json").read_text())
        signers = {s["signer_id"]: s for s in registry["signers"]}
        claimed_id = state["active_signer"]["signer_id"]
        status = signers[claimed_id]["status"]
        assert status == "active", (
            f"trust_state.json names {claimed_id!r} as active signer, "
            f"but signers.json has status={status!r}"
        )

    def test_latest_checkpoint_signer_matches_file(self):
        """trust_state.latest_checkpoint.signer_id must match the checkpoint file."""
        state = _trust_state()
        cp_file = ROOT / state["latest_checkpoint"]["file"]
        cp_data = json.loads(cp_file.read_text())
        claimed_signer = state["latest_checkpoint"]["signer_id"]
        actual_signer = cp_data.get("signer_id")
        assert claimed_signer == actual_signer, (
            f"trust_state.json says checkpoint signer={claimed_signer!r}, "
            f"but {cp_file.name} has signer_id={actual_signer!r}"
        )

    def test_latest_checkpoint_sequence_matches_file(self):
        """trust_state.latest_checkpoint.sequence_number must match the checkpoint file."""
        state = _trust_state()
        cp_file = ROOT / state["latest_checkpoint"]["file"]
        cp_data = json.loads(cp_file.read_text())
        claimed_seq = state["latest_checkpoint"]["sequence_number"]
        actual_seq = cp_data.get("sequence_number")
        assert claimed_seq == actual_seq, (
            f"trust_state.json claims sequence_number={claimed_seq}, "
            f"but {cp_file.name} has sequence_number={actual_seq}"
        )

    def test_checkpoint_filenames_are_zero_padded(self):
        """Checkpoint filenames must be zero-padded (checkpoint_XXXX.json).
        The lexical-sort ordering that test_latest_checkpoint_is_actually_latest
        depends on is only correct when filenames sort the same as sequence numbers."""
        for cp_file in (ROOT / "checkpoints").glob("checkpoint_*.json"):
            assert re.match(r"^checkpoint_\d{4}\.json$", cp_file.name), (
                f"{cp_file.name} does not match checkpoint_XXXX.json (4-digit zero-padded). "
                "All checkpoint filenames must be zero-padded to keep lexical and numeric "
                "ordering consistent."
            )

    def test_latest_checkpoint_is_actually_latest(self):
        """trust_state.latest_checkpoint must be the highest sequence on disk.
        Relies on zero-padded filenames (enforced by test_checkpoint_filenames_are_zero_padded)."""
        state = _trust_state()
        all_checkpoints = sorted((ROOT / "checkpoints").glob("checkpoint_*.json"))
        if not all_checkpoints:
            return  # no checkpoints yet
        latest_on_disk = json.loads(all_checkpoints[-1].read_text())
        claimed_seq = state["latest_checkpoint"]["sequence_number"]
        actual_latest_seq = latest_on_disk.get("sequence_number")
        assert claimed_seq == actual_latest_seq, (
            f"trust_state.json claims latest checkpoint is sequence {claimed_seq}, "
            f"but the highest checkpoint on disk is sequence {actual_latest_seq}. "
            "Update trust_state.json when a new checkpoint is merged."
        )

    def test_require_t1_matches_workflow(self):
        """trust_state.require_t1 must agree with the active checkpoint-trust.yml config."""
        state = _trust_state()
        workflow = _read_workflow("checkpoint-trust.yml")
        active_require_t1_lines = [
            line for line in workflow.splitlines()
            if "--require-t1" in line and not line.strip().startswith("#")
        ]
        workflow_enforces_t1 = bool(active_require_t1_lines)
        assert state["require_t1"] == workflow_enforces_t1, (
            f"trust_state.json says require_t1={state['require_t1']}, "
            f"but checkpoint-trust.yml {'has' if workflow_enforces_t1 else 'does not have'} "
            "an active --require-t1 flag. Keep these in sync when advancing the ratchet."
        )
