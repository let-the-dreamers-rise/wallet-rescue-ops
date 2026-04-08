"""Tests for task definitions, graders, score normalization, and difficulty progression."""

from __future__ import annotations

import subprocess
import sys

from wallet_rescue_ops import IncidentLabel, WalletRescueAction
from wallet_rescue_ops.models import ScoreBreakdown
from wallet_rescue_ops.server.app import TASKS, app
from wallet_rescue_ops.server.wallet_rescue_environment import WalletRescueEnvironment


def _finish(label: IncidentLabel) -> WalletRescueAction:
    return WalletRescueAction(
        kind="finish_incident",
        message="Contained the malicious threat and vaulted funds. Rotate wallet.",
        incident_label=label,
        confidence=0.93,
        recommended_next_steps=[
            "Rotate to a new wallet.",
            "Monitor attacker addresses.",
        ],
        rationale="Malicious entity identified and neutralised before further loss.",
    )


def test_normalized_score_in_range() -> None:
    for total in [-20.0, 0.0, 50.0, 85.5, 100.0, 120.0]:
        sb = ScoreBreakdown.normalized(total=total)
        assert 0.0 < sb.normalized_score < 1.0
        assert 0.0 < sb.total < 1.0


def test_normalized_score_values() -> None:
    assert ScoreBreakdown.normalized(total=0.0).normalized_score == 0.001
    assert ScoreBreakdown.normalized(total=100.0).normalized_score == 0.999
    assert ScoreBreakdown.normalized(total=50.0).normalized_score == 0.5
    assert ScoreBreakdown.normalized(total=50.0).total == 0.5
    assert ScoreBreakdown.normalized(total=-30.0).normalized_score == 0.001
    assert ScoreBreakdown.normalized(total=150.0).normalized_score == 0.999


def test_tasks_endpoint_returns_five_tasks() -> None:
    assert len(TASKS) == 5
    ids = {t["id"] for t in TASKS}
    assert ids == {
        "trivial_rescue",
        "easy_rescue",
        "medium_rescue",
        "hard_rescue",
        "expert_rescue",
    }


def test_every_task_seed_maps_to_valid_scenario() -> None:
    env = WalletRescueEnvironment()
    for task in TASKS:
        obs = env.reset(seed=task["seed"])
        assert obs.scenario_title, f"Task {task['id']} produced empty scenario"
        assert obs.remaining_steps > 0


def test_difficulty_progression_with_naive_agent() -> None:
    """A naive agent that skips investigation should score worse on harder tasks."""
    scores: dict[str, float] = {}
    for task in TASKS:
        env = WalletRescueEnvironment()
        obs = env.reset(seed=task["seed"])

        env.step(WalletRescueAction(kind="scan_wallet"))

        for ap in obs.active_approvals:
            if ap.status.value == "active":
                env.step(WalletRescueAction(kind="revoke_approval", target_id=ap.approval_id))

        env.step(WalletRescueAction(kind="request_secondary_approval"))

        vault = obs.policy_constraints.safe_vaults[0] if obs.policy_constraints.safe_vaults else ""
        for asset in obs.wallet_snapshot:
            if asset.amount > 0:
                try:
                    env.step(WalletRescueAction(
                        kind="transfer_to_safe_vault",
                        asset=asset.symbol,
                        amount=asset.amount,
                        destination=vault,
                    ))
                except Exception:
                    pass

        env.step(_finish(IncidentLabel.MIXED_SIGNAL_COMPROMISE))
        scores[task["id"]] = env.state.score_breakdown.normalized_score

    assert scores["expert_rescue"] < scores["easy_rescue"], (
        f"Expert ({scores['expert_rescue']}) should score lower than easy "
        f"({scores['easy_rescue']}) for a naive agent"
    )


def test_expert_task_false_positive_trap() -> None:
    """The expert task should penalise revoking the benign look-alike."""
    env = WalletRescueEnvironment()
    env.reset(seed=8)

    env.step(WalletRescueAction(kind="scan_wallet"))
    env.step(WalletRescueAction(kind="revoke_approval", target_id="apr-mix-202"))

    assert env.state.false_positive_count == 1, "Revoking apr-mix-202 should be a false positive"


def test_inference_script_runs_successfully() -> None:
    """The inference script must complete without error and produce scores."""
    result = subprocess.run(
        [sys.executable, "inference.py"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"inference.py failed:\n{result.stderr}"
    assert "[START]" in result.stdout
    assert "[STEP]" in result.stdout
    assert "[END]" in result.stdout
    assert "[SUMMARY]" in result.stdout
    assert "score=" in result.stdout
