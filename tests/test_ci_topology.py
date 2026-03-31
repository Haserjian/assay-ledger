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
