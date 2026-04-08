"""Unit tests for Wallet Rescue Ops."""

from __future__ import annotations

from wallet_rescue_ops import IncidentLabel, WalletRescueAction
from wallet_rescue_ops.server.wallet_rescue_environment import WalletRescueEnvironment


def finish_action(label: IncidentLabel) -> WalletRescueAction:
    """Build a closure action with judge-friendly language."""
    return WalletRescueAction(
        kind="finish_incident",
        message=(
            "This was a malicious spoof/drainer incident. I revoked the bad access, "
            "moved funds to the safe vault, and you should rotate to a new wallet."
        ),
        incident_label=label,
        confidence=0.94,
        recommended_next_steps=[
            "Rotate to a new wallet and move remaining trusted assets there.",
            "Monitor the attacker addresses and revoke any leftover sessions.",
        ],
        rationale=(
            "The malicious entity was identified from the suspicious approval or queued drainer, "
            "and the safest containment path was to vault funds before anything else executed."
        ),
    )


def test_seed_is_deterministic() -> None:
    env = WalletRescueEnvironment()
    obs1 = env.reset(seed=4)
    state1 = env.state
    approvals1 = [item.approval_id for item in obs1.active_approvals]

    obs2 = env.reset(seed=4)
    state2 = env.state
    approvals2 = [item.approval_id for item in obs2.active_approvals]

    assert state1.scenario_id == state2.scenario_id
    assert approvals1 == approvals2
    assert obs1.wallet_snapshot == obs2.wallet_snapshot


def test_all_12_seeded_scenarios_are_reachable() -> None:
    env = WalletRescueEnvironment()
    scenario_ids = set()
    for seed in range(12):
        env.reset(seed=seed)
        scenario_ids.add(env.state.scenario_id)
    assert len(scenario_ids) == 12


def test_invalid_inspect_target_penalizes() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=0)

    result = env.step(
        WalletRescueAction(kind="inspect_transaction", target_id="missing-target")
    )

    assert result.last_tool_result.status == "error"
    assert result.reward < 0


def test_transfer_requires_secondary_approval() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=0)

    result = env.step(
        WalletRescueAction(
            kind="transfer_to_safe_vault",
            asset="USDC",
            amount=1200.0,
            destination="vault://cold-alpha",
        )
    )

    assert result.last_tool_result.status == "error"
    assert env.state.safe_vault_usd == 0
    assert "high-value transfer without approval" in env.state.policy_violations


def test_revoking_benign_approval_counts_false_positive() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=6)

    result = env.step(
        WalletRescueAction(kind="revoke_approval", target_id="apr-mix-002")
    )

    assert result.last_tool_result.status == "warning"
    assert env.state.false_positive_count == 1
    assert result.reward < 0


def test_message_user_increments_counter() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=0)

    env.step(WalletRescueAction(kind="message_user", message="Containment in progress."))

    assert env.state.messages_sent == 1


def test_optimal_rescue_scores_high() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=0)

    env.step(WalletRescueAction(kind="scan_wallet"))
    env.step(
        WalletRescueAction(kind="inspect_transaction", target_id="apr-air-001")
    )
    env.step(WalletRescueAction(kind="revoke_approval", target_id="apr-air-001"))
    env.step(WalletRescueAction(kind="request_secondary_approval"))
    env.step(
        WalletRescueAction(
            kind="transfer_to_safe_vault",
            asset="USDC",
            amount=1200.0,
            destination="vault://cold-alpha",
        )
    )
    final_obs = env.step(finish_action(IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK))

    assert final_obs.done is True
    assert final_obs.score_breakdown is not None
    assert final_obs.score_breakdown.total >= 70
    assert env.state.funds_lost_during_episode_usd == 0


def test_missed_malicious_approval_scores_poorly() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=0)

    env.step(WalletRescueAction(kind="scan_wallet"))
    final_obs = env.step(finish_action(IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK))

    assert final_obs.done is True
    assert final_obs.score_breakdown is not None
    assert env.state.funds_lost_during_episode_usd > 0
    assert final_obs.score_breakdown.total < 20


def test_overblocking_benign_case_scores_poorly() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=7)

    env.step(WalletRescueAction(kind="scan_wallet"))
    env.step(WalletRescueAction(kind="revoke_approval", target_id="apr-mix-102"))
    env.step(WalletRescueAction(kind="revoke_approval", target_id="apr-mix-101"))
    env.step(WalletRescueAction(kind="request_secondary_approval"))
    env.step(
        WalletRescueAction(
            kind="transfer_to_safe_vault",
            asset="USDC",
            amount=1500.0,
            destination="vault://cold-charlie",
        )
    )
    final_obs = env.step(finish_action(IncidentLabel.MIXED_SIGNAL_COMPROMISE))

    assert final_obs.score_breakdown is not None
    assert env.state.false_positive_count == 1
    assert final_obs.score_breakdown.false_positive_avoidance == 0
    assert final_obs.score_breakdown.total < 70


def test_unsafe_transfer_without_secondary_approval_scores_poorly() -> None:
    env = WalletRescueEnvironment()
    env.reset(seed=2)

    env.step(
        WalletRescueAction(
            kind="transfer_to_safe_vault",
            asset="USDC",
            amount=3200.0,
            destination="vault://cold-bravo",
        )
    )
    final_obs = env.step(finish_action(IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK))

    assert final_obs.score_breakdown is not None
    assert "high-value transfer without approval" in env.state.policy_violations
    assert final_obs.score_breakdown.policy_compliance == 0
    assert final_obs.score_breakdown.total < 25
