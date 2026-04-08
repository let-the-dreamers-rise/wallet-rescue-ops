"""Demo helpers for Wallet Rescue Ops."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import IncidentLabel, WalletRescueAction
from .server.wallet_rescue_environment import WalletRescueEnvironment


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = ROOT / "outputs" / "evals"


def _finish_action(label: IncidentLabel, message: str) -> WalletRescueAction:
    return WalletRescueAction(
        kind="finish_incident",
        message=message,
        incident_label=label,
        confidence=0.95,
        recommended_next_steps=[
            "Rotate to a new wallet and move trusted funds there.",
            "Monitor attacker addresses and revoke any leftover sessions.",
        ],
        rationale=(
            "The malicious approval or queued drainer was identified from the observed wallet state, "
            "and the safest path was to contain access before anything else could execute."
        ),
    )


def _run_trajectory(actions: Iterable[WalletRescueAction], *, seed: int = 0) -> dict:
    env = WalletRescueEnvironment()
    trace: list[dict] = []

    reset_obs = env.reset(seed=seed)
    trace.append(
        {
            "type": "reset",
            "scenario": reset_obs.scenario_title,
            "summary": reset_obs.last_tool_result.summary,
            "reward": reset_obs.reward,
            "done": reset_obs.done,
        }
    )

    final_obs = reset_obs
    for action in actions:
        final_obs = env.step(action)
        trace.append(
            {
                "type": "step",
                "action": action.model_dump(mode="json", exclude_none=True),
                "summary": final_obs.last_tool_result.summary,
                "reward": final_obs.reward,
                "done": final_obs.done,
            }
        )

    return {
        "scenario_id": env.state.scenario_id,
        "title": env.state.title,
        "score_breakdown": env.state.score_breakdown.model_dump(mode="json"),
        "state": env.state.model_dump(mode="json"),
        "trace": trace,
    }


def generate_demo_artifacts(output_dir: Path | None = None) -> tuple[Path, Path]:
    """Generate good and bad demo trajectories for the README/demo."""
    target_dir = output_dir or DEFAULT_OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    success = _run_trajectory(
        [
            WalletRescueAction(kind="scan_wallet"),
            WalletRescueAction(kind="inspect_transaction", target_id="apr-air-001"),
            WalletRescueAction(kind="revoke_approval", target_id="apr-air-001"),
            WalletRescueAction(kind="request_secondary_approval"),
            WalletRescueAction(
                kind="transfer_to_safe_vault",
                asset="USDC",
                amount=1200.0,
                destination="vault://cold-alpha",
            ),
            _finish_action(
                IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK,
                (
                    "This was a fake airdrop approval attack. I revoked the malicious approval, "
                    "moved funds to the approved vault, and you should rotate to a new wallet."
                ),
            ),
        ],
        seed=0,
    )
    failure = _run_trajectory(
        [
            WalletRescueAction(kind="scan_wallet"),
            WalletRescueAction(
                kind="transfer_to_safe_vault",
                asset="USDC",
                amount=1200.0,
                destination="vault://cold-alpha",
            ),
            _finish_action(
                IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK,
                (
                    "This looked malicious, but I closed the incident early without first following policy "
                    "or neutralizing the live threat."
                ),
            ),
        ],
        seed=0,
    )

    success_path = target_dir / "success_trajectory.json"
    failure_path = target_dir / "failure_trajectory.json"
    success_path.write_text(json.dumps(success, indent=2), encoding="utf-8")
    failure_path.write_text(json.dumps(failure, indent=2), encoding="utf-8")
    return success_path, failure_path


def main() -> None:
    success_path, failure_path = generate_demo_artifacts()
    print(f"Wrote {success_path}")
    print(f"Wrote {failure_path}")


if __name__ == "__main__":
    main()
