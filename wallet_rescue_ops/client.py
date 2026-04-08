"""WebSocket client for Wallet Rescue Ops."""

from __future__ import annotations

from typing import Any

from openenv.core import EnvClient
from openenv.core.client_types import StepResult

from .models import WalletRescueAction, WalletRescueObservation, WalletRescueState


class WalletRescueOpsEnv(
    EnvClient[WalletRescueAction, WalletRescueObservation, WalletRescueState]
):
    """Persistent OpenEnv client for Wallet Rescue Ops."""

    def _step_payload(self, action: WalletRescueAction) -> dict[str, Any]:
        return action.model_dump(exclude_none=True)

    def _parse_result(
        self, payload: dict[str, Any]
    ) -> StepResult[WalletRescueObservation]:
        observation = WalletRescueObservation.model_validate(
            {
                **payload.get("observation", {}),
                "done": payload.get("done", False),
                "reward": payload.get("reward"),
            }
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict[str, Any]) -> WalletRescueState:
        return WalletRescueState.model_validate(payload)

