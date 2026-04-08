"""Typed models for Wallet Rescue Ops."""

from __future__ import annotations

from enum import Enum
from typing import Any

from openenv.core.env_server.types import Action, Observation, State
from pydantic import BaseModel, Field, model_validator


class ActionKind(str, Enum):
    """Supported actions in the environment."""

    SCAN_WALLET = "scan_wallet"
    INSPECT_TRANSACTION = "inspect_transaction"
    SIMULATE_TRANSACTION = "simulate_transaction"
    REVOKE_APPROVAL = "revoke_approval"
    TRANSFER_TO_SAFE_VAULT = "transfer_to_safe_vault"
    REQUEST_SECONDARY_APPROVAL = "request_secondary_approval"
    MESSAGE_USER = "message_user"
    FINISH_INCIDENT = "finish_incident"


class IncidentLabel(str, Enum):
    """Canonical incident labels used for final closure."""

    FAKE_AIRDROP_APPROVAL_ATTACK = "fake_airdrop_approval_attack"
    QUEUED_WALLET_DRAINER = "queued_wallet_drainer"
    MIXED_SIGNAL_COMPROMISE = "mixed_signal_compromise"
    POST_COMPROMISE_SALVAGE = "post_compromise_salvage"


class ApprovalStatus(str, Enum):
    """Approval lifecycle states."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPLOITED = "exploited"


class TransactionStatus(str, Enum):
    """Transaction lifecycle states."""

    PENDING = "pending"
    SIMULATED = "simulated"
    PREVENTED = "prevented"
    EXECUTED = "executed"


class ToolStatus(str, Enum):
    """Status for tool-like environment feedback."""

    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class WalletAsset(BaseModel):
    """Asset currently visible to the agent."""

    symbol: str = Field(..., description="Ticker symbol for the asset.")
    amount: float = Field(..., ge=0, description="Token balance.")
    usd_value: float = Field(..., ge=0, description="USD value using scenario pricing.")


class WalletApproval(BaseModel):
    """Approval shown to the agent."""

    approval_id: str
    spender: str
    asset: str
    allowance: float = Field(..., ge=0)
    usd_exposure: float = Field(..., ge=0)
    status: ApprovalStatus = ApprovalStatus.ACTIVE
    risk_hint: str = ""
    created_from: str = ""


class WalletPendingTransaction(BaseModel):
    """Pending transaction shown to the agent."""

    tx_id: str
    asset: str
    amount: float = Field(..., ge=0)
    destination: str
    status: TransactionStatus = TransactionStatus.PENDING
    risk_hint: str = ""
    preview: str = ""


class PolicyConstraints(BaseModel):
    """Policy the agent must follow."""

    safe_vaults: list[str] = Field(default_factory=list)
    high_value_threshold_usd: float = Field(default=1000.0, ge=0)
    secondary_approval_required: bool = True
    max_steps: int = Field(default=8, ge=1)


class ToolResult(BaseModel):
    """Feedback returned after each action."""

    tool: str = ""
    status: ToolStatus = ToolStatus.SUCCESS
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdown(BaseModel):
    """Human-readable judge-facing score breakdown."""

    funds_preserved: float = 0.0
    approvals_revoked: float = 0.0
    policy_compliance: float = 0.0
    false_positive_avoidance: float = 0.0
    efficiency: float = 0.0
    closure_quality: float = 0.0
    penalties: float = 0.0
    total: float = 0.0
    normalized_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Total score mapped to the 0.0-1.0 grader range.",
    )

    @model_validator(mode="after")
    def _sync_normalized(self) -> "ScoreBreakdown":
        object.__setattr__(
            self,
            "normalized_score",
            round(max(0.0, min(1.0, self.total / 100.0)), 4),
        )
        return self


class WalletRescueAction(Action):
    """Action accepted by the environment."""

    kind: ActionKind
    target_id: str | None = Field(default=None, description="Approval or transaction id.")
    asset: str | None = Field(default=None, description="Asset symbol for transfers.")
    amount: float | None = Field(
        default=None, ge=0, description="Token amount for safe-vault transfers."
    )
    destination: str | None = Field(
        default=None, description="Safe-vault destination identifier."
    )
    message: str | None = Field(
        default=None, description="Agent-authored message to the user."
    )
    incident_label: IncidentLabel | None = Field(
        default=None, description="Final incident classification."
    )
    confidence: float | None = Field(
        default=None, ge=0.0, le=1.0, description="Confidence for finish_incident."
    )
    recommended_next_steps: list[str] = Field(default_factory=list)
    rationale: str | None = Field(
        default=None, description="Short explanation of why the incident is closed."
    )

    @model_validator(mode="after")
    def validate_action_requirements(self) -> "WalletRescueAction":
        """Enforce per-action required fields."""
        if self.kind in {
            ActionKind.INSPECT_TRANSACTION,
            ActionKind.SIMULATE_TRANSACTION,
            ActionKind.REVOKE_APPROVAL,
        } and not self.target_id:
            raise ValueError(f"{self.kind.value} requires target_id")

        if self.kind == ActionKind.TRANSFER_TO_SAFE_VAULT:
            if not self.asset or self.amount is None or not self.destination:
                raise ValueError(
                    "transfer_to_safe_vault requires asset, amount, and destination"
                )

        if self.kind == ActionKind.MESSAGE_USER and not self.message:
            raise ValueError("message_user requires message")

        if self.kind == ActionKind.FINISH_INCIDENT:
            missing = []
            if not self.message:
                missing.append("message")
            if self.incident_label is None:
                missing.append("incident_label")
            if self.confidence is None:
                missing.append("confidence")
            if not self.recommended_next_steps:
                missing.append("recommended_next_steps")
            if not self.rationale:
                missing.append("rationale")
            if missing:
                raise ValueError(
                    f"finish_incident missing required fields: {', '.join(missing)}"
                )

        return self


class WalletRescueObservation(Observation):
    """Observation returned after reset and step."""

    scenario_title: str = ""
    user_context: str = ""
    wallet_snapshot: list[WalletAsset] = Field(default_factory=list)
    pending_transactions: list[WalletPendingTransaction] = Field(default_factory=list)
    active_approvals: list[WalletApproval] = Field(default_factory=list)
    policy_constraints: PolicyConstraints = Field(default_factory=PolicyConstraints)
    last_tool_result: ToolResult = Field(default_factory=ToolResult)
    remaining_steps: int = 0
    score_breakdown: ScoreBreakdown | None = None


class WalletRescueState(State):
    """Internal state, visible through /state for debugging and grading."""

    seed: int = 0
    scenario_id: str = ""
    family: str = ""
    title: str = ""
    safe_vault_destination: str = ""
    recoverable_usd: float = 0.0
    safe_vault_usd: float = 0.0
    funds_preserved_usd: float = 0.0
    funds_lost_during_episode_usd: float = 0.0
    already_lost_before_episode_usd: float = 0.0
    malicious_approvals: list[str] = Field(default_factory=list)
    malicious_transactions: list[str] = Field(default_factory=list)
    benign_approvals: list[str] = Field(default_factory=list)
    revoked_approvals: list[str] = Field(default_factory=list)
    neutralized_transactions: list[str] = Field(default_factory=list)
    policy_approval_granted: bool = False
    policy_satisfied: bool = False
    policy_violations: list[str] = Field(default_factory=list)
    false_positive_count: int = 0
    messages_sent: int = 0
    final_label: str | None = None
    final_confidence: float | None = None
    finished: bool = False
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    reference_facts: list[str] = Field(default_factory=list)

