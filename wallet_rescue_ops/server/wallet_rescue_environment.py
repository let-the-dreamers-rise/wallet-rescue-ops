"""Wallet Rescue Ops environment implementation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata

try:
    from ..episodes import ApprovalSpec, TransactionSpec, WalletEpisodeSpec, get_episode
    from ..models import (
        ActionKind,
        ApprovalStatus,
        PolicyConstraints,
        ScoreBreakdown,
        ToolResult,
        ToolStatus,
        TransactionStatus,
        WalletApproval,
        WalletAsset,
        WalletPendingTransaction,
        WalletRescueAction,
        WalletRescueObservation,
        WalletRescueState,
    )
except ImportError:
    from episodes import ApprovalSpec, TransactionSpec, WalletEpisodeSpec, get_episode  # type: ignore[no-redef]
    from models import (  # type: ignore[no-redef]
        ActionKind,
        ApprovalStatus,
        PolicyConstraints,
        ScoreBreakdown,
        ToolResult,
        ToolStatus,
        TransactionStatus,
        WalletApproval,
        WalletAsset,
        WalletPendingTransaction,
        WalletRescueAction,
        WalletRescueObservation,
        WalletRescueState,
    )


def round2(value: float) -> float:
    """Round floats consistently for user-facing state."""
    return round(value + 1e-9, 2)


@dataclass
class ApprovalRuntime:
    spec: ApprovalSpec
    status: ApprovalStatus = ApprovalStatus.ACTIVE
    inspected: bool = False
    simulated: bool = False


@dataclass
class TransactionRuntime:
    spec: TransactionSpec
    status: TransactionStatus = TransactionStatus.PENDING
    inspected: bool = False
    simulated: bool = False


class WalletRescueEnvironment(
    Environment[WalletRescueAction, WalletRescueObservation, WalletRescueState]
):
    """High-stakes wallet incident-response environment."""

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        super().__init__()
        self._reset_counter = 0
        self._episode: WalletEpisodeSpec | None = None
        self._asset_prices: dict[str, float] = {}
        self._balances: dict[str, float] = {}
        self._safe_vault_balances: dict[str, float] = defaultdict(float)
        self._approvals: dict[str, ApprovalRuntime] = {}
        self._transactions: dict[str, TransactionRuntime] = {}
        self._penalties: list[tuple[str, float]] = []
        self._closure_action: WalletRescueAction | None = None
        self._finished = False
        self._state = WalletRescueState(episode_id=str(uuid4()), step_count=0)

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs: Any,
    ) -> WalletRescueObservation:
        """Reset the environment to a deterministic scenario."""
        scenario_id = kwargs.get("scenario_id")
        chosen_seed, episode = get_episode(
            seed,
            scenario_id=scenario_id,
            cycle_index=self._reset_counter,
        )
        self._reset_counter += 1
        self._episode = episode
        self._finished = False
        self._closure_action = None
        self._penalties = []
        self._asset_prices = {asset.symbol: asset.usd_price for asset in episode.assets}
        self._balances = {asset.symbol: asset.amount for asset in episode.assets}
        self._safe_vault_balances = defaultdict(float)
        self._approvals = {
            item.approval_id: ApprovalRuntime(spec=item) for item in episode.approvals
        }
        self._transactions = {
            item.tx_id: TransactionRuntime(spec=item)
            for item in episode.pending_transactions
        }

        self._state = WalletRescueState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            seed=chosen_seed,
            scenario_id=episode.episode_key,
            family=episode.family,
            title=episode.title,
            safe_vault_destination=episode.safe_vault_destination,
            recoverable_usd=episode.recoverable_usd,
            safe_vault_usd=0.0,
            funds_preserved_usd=0.0,
            funds_lost_during_episode_usd=0.0,
            already_lost_before_episode_usd=episode.already_lost_before_episode_usd,
            malicious_approvals=[
                item.approval_id for item in episode.approvals if item.is_malicious
            ],
            malicious_transactions=[
                item.tx_id
                for item in episode.pending_transactions
                if item.is_malicious
            ],
            benign_approvals=[
                item.approval_id for item in episode.approvals if not item.is_malicious
            ],
            revoked_approvals=[],
            neutralized_transactions=[],
            policy_approval_granted=False,
            policy_satisfied=False,
            policy_violations=[],
            false_positive_count=0,
            messages_sent=0,
            final_label=None,
            final_confidence=None,
            finished=False,
            score_breakdown=ScoreBreakdown(),
            reference_facts=list(episode.reference_facts),
        )

        return self._make_observation(
            ToolResult(
                tool="reset",
                status=ToolStatus.SUCCESS,
                summary=f"{episode.title} ready. Recover and explain the incident.",
                details={
                    "scenario_id": episode.episode_key,
                    "family": episode.family,
                    "safe_vault": episode.safe_vault_destination,
                },
            ),
            reward=0.001,
            done=False,
        )

    @property
    def state(self) -> WalletRescueState:
        """Return the internal environment state."""
        return self._state

    def get_metadata(self) -> EnvironmentMetadata:
        """Describe the environment for docs and UI."""
        return EnvironmentMetadata(
            name="Wallet Rescue Ops",
            description=(
                "Incident-response environment for rescuing compromised crypto wallets "
                "under policy constraints and partial information."
            ),
            version="0.1.0",
        )

    def step(
        self,
        action: WalletRescueAction,
        timeout_s: float | None = None,
        **kwargs: Any,
    ) -> WalletRescueObservation:
        """Execute a single action in the environment."""
        del timeout_s, kwargs
        if self._episode is None:
            return self.reset()

        if self._finished:
            return self._make_observation(
                ToolResult(
                    tool=action.kind.value,
                    status=ToolStatus.WARNING,
                    summary="Episode already finished. Reset before taking more actions.",
                ),
                reward=0.001,
                done=True,
            )

        previous_total = self._state.score_breakdown.total
        self._state.step_count += 1

        handler = {
            ActionKind.SCAN_WALLET: self._handle_scan_wallet,
            ActionKind.INSPECT_TRANSACTION: self._handle_inspect,
            ActionKind.SIMULATE_TRANSACTION: self._handle_simulate,
            ActionKind.REVOKE_APPROVAL: self._handle_revoke,
            ActionKind.TRANSFER_TO_SAFE_VAULT: self._handle_transfer,
            ActionKind.REQUEST_SECONDARY_APPROVAL: self._handle_request_approval,
            ActionKind.MESSAGE_USER: self._handle_message_user,
            ActionKind.FINISH_INCIDENT: self._handle_finish,
        }[action.kind]

        tool_result = handler(action)

        if not self._finished:
            notes = self._advance_threats(force=False)
            if notes:
                tool_result = self._attach_system_notes(tool_result, notes)

        if not self._finished and self._state.step_count >= self._episode.max_steps:
            self._record_penalty("step_budget_exhausted", -8.0)
            self._finalize_episode(reason="step_budget_exhausted")
            tool_result = self._attach_system_notes(
                tool_result,
                ["Step budget exhausted. Outstanding threats were settled as a failure state."],
            )

        self._refresh_scorebreakdown(finalize=self._finished)
        raw_reward = round2(self._state.score_breakdown.total - previous_total)
        reward = round(max(0.001, min(0.999, raw_reward)), 4)
        return self._make_observation(tool_result, reward=reward, done=self._finished)

    def _handle_scan_wallet(self, action: WalletRescueAction) -> ToolResult:
        del action
        suspicious_approvals = [
            approval.spec.approval_id
            for approval in self._approvals.values()
            if approval.spec.is_malicious and approval.status == ApprovalStatus.ACTIVE
        ]
        suspicious_txs = [
            tx.spec.tx_id
            for tx in self._transactions.values()
            if tx.spec.is_malicious
            and tx.status in {TransactionStatus.PENDING, TransactionStatus.SIMULATED}
        ]
        return ToolResult(
            tool=ActionKind.SCAN_WALLET.value,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Scan found {len(suspicious_approvals)} suspicious approval(s) and "
                f"{len(suspicious_txs)} suspicious pending transaction(s)."
            ),
            details={
                "suspicious_approvals": suspicious_approvals,
                "suspicious_transactions": suspicious_txs,
                "safe_vault": self._episode.safe_vault_destination,
                "high_value_threshold_usd": self._episode.high_value_threshold_usd,
            },
        )

    def _handle_inspect(self, action: WalletRescueAction) -> ToolResult:
        target_id = action.target_id or ""
        if target_id in self._approvals:
            runtime = self._approvals[target_id]
            runtime.inspected = True
            return ToolResult(
                tool=ActionKind.INSPECT_TRANSACTION.value,
                status=ToolStatus.WARNING if runtime.spec.is_malicious else ToolStatus.SUCCESS,
                summary=runtime.spec.inspection_summary,
                details={
                    "target_type": "approval",
                    "approval_id": runtime.spec.approval_id,
                    "spender": runtime.spec.spender,
                    "created_from": runtime.spec.created_from,
                    "usd_exposure": runtime.spec.usd_exposure,
                },
            )

        if target_id in self._transactions:
            runtime = self._transactions[target_id]
            runtime.inspected = True
            return ToolResult(
                tool=ActionKind.INSPECT_TRANSACTION.value,
                status=ToolStatus.WARNING if runtime.spec.is_malicious else ToolStatus.SUCCESS,
                summary=runtime.spec.inspection_summary,
                details={
                    "target_type": "transaction",
                    "tx_id": runtime.spec.tx_id,
                    "destination": runtime.spec.destination,
                    "preview": runtime.spec.preview,
                },
            )

        self._record_penalty("inspect_invalid_target", -4.0)
        return ToolResult(
            tool=ActionKind.INSPECT_TRANSACTION.value,
            status=ToolStatus.ERROR,
            summary=f"Unknown target_id: {target_id}",
        )

    def _handle_simulate(self, action: WalletRescueAction) -> ToolResult:
        target_id = action.target_id or ""
        if target_id in self._approvals:
            runtime = self._approvals[target_id]
            runtime.simulated = True
            return ToolResult(
                tool=ActionKind.SIMULATE_TRANSACTION.value,
                status=ToolStatus.WARNING if runtime.spec.is_malicious else ToolStatus.SUCCESS,
                summary=runtime.spec.simulation_summary,
                details={
                    "target_type": "approval",
                    "approval_id": runtime.spec.approval_id,
                    "projected_loss_usd": runtime.spec.usd_exposure if runtime.spec.is_malicious else 0.0,
                },
            )

        if target_id in self._transactions:
            runtime = self._transactions[target_id]
            runtime.simulated = True
            if runtime.status == TransactionStatus.PENDING:
                runtime.status = TransactionStatus.SIMULATED
            return ToolResult(
                tool=ActionKind.SIMULATE_TRANSACTION.value,
                status=ToolStatus.WARNING if runtime.spec.is_malicious else ToolStatus.SUCCESS,
                summary=runtime.spec.simulation_summary,
                details={
                    "target_type": "transaction",
                    "tx_id": runtime.spec.tx_id,
                    "projected_loss_usd": self._asset_usd_value(
                        runtime.spec.asset, runtime.spec.amount
                    )
                    if runtime.spec.is_malicious
                    else 0.0,
                },
            )

        self._record_penalty("simulate_invalid_target", -4.0)
        return ToolResult(
            tool=ActionKind.SIMULATE_TRANSACTION.value,
            status=ToolStatus.ERROR,
            summary=f"Unknown target_id: {target_id}",
        )

    def _handle_revoke(self, action: WalletRescueAction) -> ToolResult:
        target_id = action.target_id or ""
        runtime = self._approvals.get(target_id)
        if runtime is None:
            self._record_penalty("revoke_invalid_target", -5.0)
            return ToolResult(
                tool=ActionKind.REVOKE_APPROVAL.value,
                status=ToolStatus.ERROR,
                summary=f"{target_id} is not a revocable approval id.",
            )

        if runtime.status == ApprovalStatus.REVOKED:
            return ToolResult(
                tool=ActionKind.REVOKE_APPROVAL.value,
                status=ToolStatus.WARNING,
                summary=f"{target_id} was already revoked.",
            )

        if runtime.status == ApprovalStatus.EXPLOITED:
            return ToolResult(
                tool=ActionKind.REVOKE_APPROVAL.value,
                status=ToolStatus.WARNING,
                summary=f"{target_id} was already exploited. Revocation is now too late for the drained funds.",
            )

        runtime.status = ApprovalStatus.REVOKED
        if runtime.spec.is_malicious:
            if target_id not in self._state.revoked_approvals:
                self._state.revoked_approvals.append(target_id)
            return ToolResult(
                tool=ActionKind.REVOKE_APPROVAL.value,
                status=ToolStatus.SUCCESS,
                summary=f"Revoked malicious approval {target_id}.",
                details={"spender": runtime.spec.spender},
            )

        self._state.false_positive_count += 1
        self._record_penalty("revoked_benign_approval", -10.0)
        return ToolResult(
            tool=ActionKind.REVOKE_APPROVAL.value,
            status=ToolStatus.WARNING,
            summary=f"Revoked benign approval {target_id}; this was an avoidable false positive.",
            details={"spender": runtime.spec.spender},
        )

    def _handle_transfer(self, action: WalletRescueAction) -> ToolResult:
        asset = action.asset or ""
        amount = action.amount or 0.0
        destination = action.destination or ""
        current_balance = self._balances.get(asset, 0.0)

        if asset not in self._balances:
            self._record_penalty("transfer_unknown_asset", -5.0)
            return ToolResult(
                tool=ActionKind.TRANSFER_TO_SAFE_VAULT.value,
                status=ToolStatus.ERROR,
                summary=f"{asset} is not present in the wallet snapshot.",
            )

        if amount <= 0 or amount > current_balance:
            self._record_penalty("transfer_invalid_amount", -5.0)
            return ToolResult(
                tool=ActionKind.TRANSFER_TO_SAFE_VAULT.value,
                status=ToolStatus.ERROR,
                summary=f"Invalid amount {amount} for asset {asset}. Current balance is {current_balance}.",
            )

        if destination != self._episode.safe_vault_destination:
            self._state.policy_violations.append("wrong destination")
            self._record_penalty("wrong_destination", -25.0)
            return ToolResult(
                tool=ActionKind.TRANSFER_TO_SAFE_VAULT.value,
                status=ToolStatus.ERROR,
                summary=f"{destination} is not the approved safe vault. Use {self._episode.safe_vault_destination}.",
            )

        usd_value = self._asset_usd_value(asset, amount)
        needs_secondary = (
            self._episode.secondary_approval_required
            and usd_value >= self._episode.high_value_threshold_usd
        )
        if needs_secondary and not self._state.policy_approval_granted:
            self._state.policy_violations.append("high-value transfer without approval")
            self._record_penalty("missing_secondary_approval", -20.0)
            return ToolResult(
                tool=ActionKind.TRANSFER_TO_SAFE_VAULT.value,
                status=ToolStatus.ERROR,
                summary="High-value transfer blocked. Request secondary approval before moving funds.",
            )

        self._balances[asset] = round2(self._balances[asset] - amount)
        self._safe_vault_balances[asset] = round2(self._safe_vault_balances[asset] + amount)
        if needs_secondary:
            self._state.policy_satisfied = True
            self._state.policy_approval_granted = False

        self._mark_prevented_transactions()
        return ToolResult(
            tool=ActionKind.TRANSFER_TO_SAFE_VAULT.value,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Moved {amount} {asset} to {destination} "
                f"({round2(usd_value)} USD protected in the safe vault)."
            ),
            details={
                "asset": asset,
                "amount": amount,
                "destination": destination,
                "usd_value": round2(usd_value),
            },
        )

    def _handle_request_approval(self, action: WalletRescueAction) -> ToolResult:
        del action
        if self._state.policy_approval_granted:
            return ToolResult(
                tool=ActionKind.REQUEST_SECONDARY_APPROVAL.value,
                status=ToolStatus.WARNING,
                summary="Secondary approval is already granted for the next high-value transfer.",
            )

        self._state.policy_approval_granted = True
        return ToolResult(
            tool=ActionKind.REQUEST_SECONDARY_APPROVAL.value,
            status=ToolStatus.SUCCESS,
            summary="Secondary approval granted for the next compliant high-value vault transfer.",
            details={"safe_vault": self._episode.safe_vault_destination},
        )

    def _handle_message_user(self, action: WalletRescueAction) -> ToolResult:
        self._state.messages_sent += 1
        return ToolResult(
            tool=ActionKind.MESSAGE_USER.value,
            status=ToolStatus.SUCCESS,
            summary="User message recorded.",
            details={"message": action.message or ""},
        )

    def _handle_finish(self, action: WalletRescueAction) -> ToolResult:
        self._closure_action = action
        self._state.final_label = action.incident_label.value if action.incident_label else None
        self._state.final_confidence = action.confidence
        self._finalize_episode(reason="agent_finished")
        return ToolResult(
            tool=ActionKind.FINISH_INCIDENT.value,
            status=ToolStatus.SUCCESS,
            summary="Incident closed and scored.",
            details={
                "final_label": self._state.final_label,
                "score_total": self._state.score_breakdown.total,
            },
        )

    def _finalize_episode(self, reason: str) -> None:
        if self._finished:
            return

        unresolved = self._count_unresolved_threats()
        if unresolved:
            self._record_penalty("unresolved_threats", -6.0 * unresolved)

        settle_notes = self._advance_threats(force=True)
        if settle_notes and reason == "agent_finished":
            self._record_penalty("finished_with_live_threats", -6.0)

        self._finished = True
        self._state.finished = True
        self._refresh_scorebreakdown(finalize=True)

    def _advance_threats(self, *, force: bool) -> list[str]:
        notes: list[str] = []

        for runtime in self._transactions.values():
            if (
                runtime.spec.is_malicious
                and runtime.status in {TransactionStatus.PENDING, TransactionStatus.SIMULATED}
                and (force or self._should_trigger(runtime.spec.trigger_step))
            ):
                balance = self._balances.get(runtime.spec.asset, 0.0)
                if balance <= 0:
                    runtime.status = TransactionStatus.PREVENTED
                    if runtime.spec.tx_id not in self._state.neutralized_transactions:
                        self._state.neutralized_transactions.append(runtime.spec.tx_id)
                    notes.append(
                        f"{runtime.spec.tx_id} could not execute because the vulnerable balance was already moved."
                    )
                    continue

                drained_amount = min(balance, runtime.spec.amount)
                self._balances[runtime.spec.asset] = round2(balance - drained_amount)
                runtime.status = TransactionStatus.EXECUTED
                lost_usd = self._asset_usd_value(runtime.spec.asset, drained_amount)
                self._state.funds_lost_during_episode_usd = round2(
                    self._state.funds_lost_during_episode_usd + lost_usd
                )
                self._record_penalty("malicious_tx_executed", -18.0)
                notes.append(
                    f"{runtime.spec.tx_id} executed and drained {drained_amount} {runtime.spec.asset}."
                )

        for runtime in self._approvals.values():
            if (
                runtime.spec.is_malicious
                and runtime.status == ApprovalStatus.ACTIVE
                and (force or self._should_trigger(runtime.spec.trigger_step))
            ):
                balance = self._balances.get(runtime.spec.asset, 0.0)
                if balance <= 0:
                    continue
                drained_usd = min(
                    self._asset_usd_value(runtime.spec.asset, balance),
                    runtime.spec.usd_exposure,
                )
                drained_amount = min(
                    balance,
                    round2(drained_usd / max(self._asset_prices[runtime.spec.asset], 0.0001)),
                )
                if drained_amount <= 0:
                    continue
                self._balances[runtime.spec.asset] = round2(balance - drained_amount)
                runtime.status = ApprovalStatus.EXPLOITED
                self._state.funds_lost_during_episode_usd = round2(
                    self._state.funds_lost_during_episode_usd
                    + self._asset_usd_value(runtime.spec.asset, drained_amount)
                )
                self._record_penalty("approval_exploited", -14.0)
                notes.append(
                    f"{runtime.spec.approval_id} was exploited and drained {drained_amount} {runtime.spec.asset}."
                )

        self._mark_prevented_transactions()
        return notes

    def _mark_prevented_transactions(self) -> None:
        for runtime in self._transactions.values():
            if not runtime.spec.is_malicious:
                continue
            if runtime.status in {TransactionStatus.EXECUTED, TransactionStatus.PREVENTED}:
                continue
            if self._balances.get(runtime.spec.asset, 0.0) <= 0:
                runtime.status = TransactionStatus.PREVENTED
                if runtime.spec.tx_id not in self._state.neutralized_transactions:
                    self._state.neutralized_transactions.append(runtime.spec.tx_id)

    def _should_trigger(self, trigger_step: int | None) -> bool:
        return trigger_step is not None and self._state.step_count >= trigger_step

    def _asset_usd_value(self, asset: str, amount: float) -> float:
        return round2(amount * self._asset_prices[asset])

    def _record_penalty(self, code: str, amount: float) -> None:
        self._penalties.append((code, amount))

    def _refresh_scorebreakdown(self, *, finalize: bool) -> None:
        malicious_total = len(self._state.malicious_approvals) or 1
        revoked_total = len(self._state.revoked_approvals)
        safe_vault_usd = round2(
            sum(
                self._asset_usd_value(asset, amount)
                for asset, amount in self._safe_vault_balances.items()
            )
        )
        funds_preserved = round2(
            40.0 * safe_vault_usd / max(self._state.recoverable_usd, 1.0)
        )
        approvals_revoked = round2(20.0 * revoked_total / malicious_total)
        policy_blocked = any(
            "wrong destination" in violation or "high-value" in violation
            for violation in self._state.policy_violations
        )
        policy_compliance = 15.0 if self._state.policy_satisfied and not policy_blocked else 0.0
        false_positive_avoidance = (
            10.0 if finalize and self._state.false_positive_count == 0 else 0.0
        )
        efficiency = 0.0
        if finalize:
            ideal_steps = len(self._episode.ideal_actions)
            efficiency = round2(
                max(0.0, 10.0 - max(0, self._state.step_count - ideal_steps) * 2.0)
            )
        closure_quality = self._score_closure() if finalize else 0.0
        penalties = round2(sum(amount for _, amount in self._penalties))
        total = round2(
            funds_preserved
            + approvals_revoked
            + policy_compliance
            + false_positive_avoidance
            + efficiency
            + closure_quality
            + penalties
        )

        self._state.safe_vault_usd = safe_vault_usd
        self._state.funds_preserved_usd = safe_vault_usd
        self._state.score_breakdown = ScoreBreakdown.normalized(
            funds_preserved=funds_preserved,
            approvals_revoked=approvals_revoked,
            policy_compliance=policy_compliance,
            false_positive_avoidance=false_positive_avoidance,
            efficiency=efficiency,
            closure_quality=closure_quality,
            penalties=penalties,
            total=total,
        )

    def _score_closure(self) -> float:
        if self._closure_action is None:
            return 0.0

        text = " ".join(
            [
                self._closure_action.message or "",
                self._closure_action.rationale or "",
                " ".join(self._closure_action.recommended_next_steps),
            ]
        ).lower()
        score = 0.0
        if self._closure_action.incident_label == self._episode.expected_incident_label:
            score += 1.0
        if any(keyword in text for keyword in ("malicious", "drainer", "spoof", "fake")):
            score += 1.0
        if any(keyword in text for keyword in ("revoke", "revoked", "transfer", "vault")):
            score += 1.0
        if any(keyword in text for keyword in ("rotate", "new wallet", "hardware wallet", "monitor")):
            score += 1.0
        if len(self._closure_action.recommended_next_steps) >= 2:
            score += 1.0
        return score

    def _count_unresolved_threats(self) -> int:
        active_approvals = sum(
            1
            for runtime in self._approvals.values()
            if runtime.spec.is_malicious and runtime.status == ApprovalStatus.ACTIVE
        )
        active_txs = sum(
            1
            for runtime in self._transactions.values()
            if runtime.spec.is_malicious
            and runtime.status in {TransactionStatus.PENDING, TransactionStatus.SIMULATED}
        )
        return active_approvals + active_txs

    def _attach_system_notes(
        self, tool_result: ToolResult, notes: list[str]
    ) -> ToolResult:
        details = dict(tool_result.details)
        details["system_notes"] = notes
        status = tool_result.status
        if notes and status == ToolStatus.SUCCESS:
            status = ToolStatus.WARNING
        summary = tool_result.summary
        if notes:
            summary = f"{summary} System notes: {' '.join(notes)}"
        return ToolResult(
            tool=tool_result.tool,
            status=status,
            summary=summary,
            details=details,
        )

    def _make_wallet_snapshot(self) -> list[WalletAsset]:
        return [
            WalletAsset(
                symbol=symbol,
                amount=round2(self._balances.get(symbol, 0.0)),
                usd_value=self._asset_usd_value(symbol, self._balances.get(symbol, 0.0)),
            )
            for symbol in sorted(self._asset_prices)
        ]

    def _make_approval_list(self) -> list[WalletApproval]:
        return [
            WalletApproval(
                approval_id=runtime.spec.approval_id,
                spender=runtime.spec.spender,
                asset=runtime.spec.asset,
                allowance=runtime.spec.allowance,
                usd_exposure=runtime.spec.usd_exposure,
                status=runtime.status,
                risk_hint=runtime.spec.risk_hint,
                created_from=runtime.spec.created_from,
            )
            for runtime in sorted(
                self._approvals.values(), key=lambda item: item.spec.approval_id
            )
        ]

    def _make_transaction_list(self) -> list[WalletPendingTransaction]:
        items: list[WalletPendingTransaction] = []
        for runtime in sorted(
            self._transactions.values(), key=lambda item: item.spec.tx_id
        ):
            status = runtime.status
            if runtime.simulated and status == TransactionStatus.PENDING:
                status = TransactionStatus.SIMULATED
            items.append(
                WalletPendingTransaction(
                    tx_id=runtime.spec.tx_id,
                    asset=runtime.spec.asset,
                    amount=runtime.spec.amount,
                    destination=runtime.spec.destination,
                    status=status,
                    risk_hint=runtime.spec.risk_hint,
                    preview=runtime.spec.preview,
                )
            )
        return items

    def _make_observation(
        self, tool_result: ToolResult, *, reward: float, done: bool
    ) -> WalletRescueObservation:
        return WalletRescueObservation(
            scenario_title=self._episode.title,
            user_context=self._episode.user_context,
            wallet_snapshot=self._make_wallet_snapshot(),
            pending_transactions=self._make_transaction_list(),
            active_approvals=self._make_approval_list(),
            policy_constraints=PolicyConstraints(
                safe_vaults=[self._episode.safe_vault_destination],
                high_value_threshold_usd=self._episode.high_value_threshold_usd,
                secondary_approval_required=self._episode.secondary_approval_required,
                max_steps=self._episode.max_steps,
            ),
            last_tool_result=tool_result,
            remaining_steps=max(self._episode.max_steps - self._state.step_count, 0),
            score_breakdown=None,
            done=done,
            reward=reward,
        )
