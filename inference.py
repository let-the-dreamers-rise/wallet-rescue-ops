#!/usr/bin/env python3
"""Baseline inference script for Wallet Rescue Ops.

Uses an LLM (via OpenAI-compatible client) to play through each task,
or falls back to a deterministic heuristic agent when credentials are absent.
The heuristic uses ONLY observation data -- no internal state access.

Required env vars:  API_BASE_URL, MODEL_NAME, HF_TOKEN (or OPENAI_API_KEY)
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

from openai import OpenAI

from wallet_rescue_ops.models import (
    ActionKind,
    IncidentLabel,
    WalletRescueAction,
    WalletRescueObservation,
)
from wallet_rescue_ops.server.wallet_rescue_environment import WalletRescueEnvironment

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
HF_TOKEN = os.getenv("HF_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

_api_key = HF_TOKEN or OPENAI_API_KEY or ""
USE_LLM = bool(API_BASE_URL and MODEL_NAME and _api_key)

if USE_LLM:
    client = OpenAI(base_url=API_BASE_URL, api_key=_api_key)
else:
    client = None

TASKS = [
    {"task_id": "trivial_rescue", "seed": 9, "name": "Already Drained Once"},
    {"task_id": "easy_rescue", "seed": 0, "name": "Fake Airdrop Containment"},
    {"task_id": "medium_rescue", "seed": 6, "name": "Mixed Signal Triage"},
    {"task_id": "hard_rescue", "seed": 10, "name": "Post-Compromise Salvage"},
    {"task_id": "expert_rescue", "seed": 8, "name": "Market Maker or Drainer"},
]

FAMILY_KEYWORDS_TO_LABEL: list[tuple[list[str], IncidentLabel]] = [
    (["airdrop", "mint", "reward center", "fake"],
     IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK),
    (["drainer", "sweep", "queued", "bridge", "payroll"],
     IncidentLabel.QUEUED_WALLET_DRAINER),
    (["mixed", "maze", "market", "staking exit", "panic"],
     IncidentLabel.MIXED_SIGNAL_COMPROMISE),
    (["drained once", "partial", "salvage", "compromise", "aftercare", "support"],
     IncidentLabel.POST_COMPROMISE_SALVAGE),
]

SYSTEM_PROMPT = """\
You are a wallet incident-response agent inside the Wallet Rescue Ops environment.
Your goal: maximise the normalised score (0.0-1.0) by investigating threats, revoking \
malicious approvals, moving funds to the approved safe vault, and closing the incident \
with a clear explanation.

### Available actions (reply with **one** JSON object, nothing else)

1. {"kind":"scan_wallet"}
2. {"kind":"inspect_transaction","target_id":"<approval_or_tx_id>"}
3. {"kind":"simulate_transaction","target_id":"<approval_or_tx_id>"}
4. {"kind":"revoke_approval","target_id":"<approval_id>"}
5. {"kind":"request_secondary_approval"}
6. {"kind":"transfer_to_safe_vault","asset":"<SYMBOL>","amount":<number>,"destination":"<vault>"}
7. {"kind":"message_user","message":"<text>"}
8. {"kind":"finish_incident","message":"<user-facing explanation>",\
"incident_label":"<label>","confidence":<0-1>,\
"recommended_next_steps":["step1","step2"],"rationale":"<short why>"}

Labels: fake_airdrop_approval_attack | queued_wallet_drainer | mixed_signal_compromise | post_compromise_salvage

### Strategy
- Always start with scan_wallet.
- Inspect/simulate suspicious items BEFORE revoking -- you get penalised for false positives.
- Revoke ONLY malicious approvals (false positives cost 10 points).
- request_secondary_approval BEFORE any high-value vault transfer.
- transfer_to_safe_vault using the exact vault from policy_constraints.safe_vaults.
- Transfer the highest-value asset first to prevent drainers.
- finish_incident with all required fields and at least 2 next-steps.
- When two items look similar, ALWAYS inspect both before deciding which to revoke.

Respond with ONLY a single JSON object. No markdown, no commentary.\
"""


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------

def emit(tag: str, payload: dict[str, Any]) -> None:
    print(f"[{tag}] {json.dumps(payload, default=str)}", flush=True)


def ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Observation formatting
# ---------------------------------------------------------------------------

def obs_to_text(obs: WalletRescueObservation) -> str:
    parts = [
        f"Scenario: {obs.scenario_title}",
        f"Context: {obs.user_context}",
        f"Remaining steps: {obs.remaining_steps}",
        "",
        "== Wallet ==",
    ]
    for a in obs.wallet_snapshot:
        parts.append(f"  {a.symbol}: {a.amount} (${a.usd_value})")
    parts.append("")

    if obs.active_approvals:
        parts.append("== Approvals ==")
        for ap in obs.active_approvals:
            parts.append(
                f"  [{ap.status.value}] {ap.approval_id}  spender={ap.spender}  "
                f"asset={ap.asset}  exposure=${ap.usd_exposure}  hint=\"{ap.risk_hint}\""
            )
        parts.append("")

    if obs.pending_transactions:
        parts.append("== Pending Transactions ==")
        for tx in obs.pending_transactions:
            parts.append(
                f"  [{tx.status.value}] {tx.tx_id}  asset={tx.asset}  "
                f"amount={tx.amount}  dest={tx.destination}  hint=\"{tx.risk_hint}\""
            )
        parts.append("")

    pc = obs.policy_constraints
    parts.append(
        f"Policy: safe_vaults={pc.safe_vaults}  "
        f"high_value_threshold=${pc.high_value_threshold_usd}  "
        f"secondary_approval_required={pc.secondary_approval_required}"
    )
    parts.append("")
    parts.append(
        f"Last tool: [{obs.last_tool_result.status.value}] "
        f"{obs.last_tool_result.tool} -- {obs.last_tool_result.summary}"
    )
    if obs.last_tool_result.details:
        parts.append(f"  details: {json.dumps(obs.last_tool_result.details, default=str)}")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM agent
# ---------------------------------------------------------------------------

def extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
        text = text.strip()
    match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


def llm_decide(messages: list[dict[str, str]]) -> tuple[dict[str, Any], str]:
    resp = client.chat.completions.create(  # type: ignore[union-attr]
        model=MODEL_NAME,
        messages=messages,
        temperature=0.0,
        max_tokens=600,
    )
    raw = resp.choices[0].message.content or "{}"
    return extract_json(raw), raw


# ---------------------------------------------------------------------------
# Observation-only heuristic (NO env.state access)
# ---------------------------------------------------------------------------

def _looks_suspicious(hint: str) -> bool:
    """Guess whether an approval/tx is suspicious from its risk_hint alone."""
    hint_lower = hint.lower()
    signals = [
        "not allowlisted", "spoofed", "fake", "spoof", "new", "suspicious",
        "full", "entire", "one character off", "misspelled", "absent",
        "no prior history", "no relationship", "unknown",
    ]
    return any(s in hint_lower for s in signals)


def _looks_benign(hint: str) -> bool:
    hint_lower = hint.lower()
    signals = ["allowlisted", "known", "existing", "small", "tiny", "user-owned"]
    return any(s in hint_lower for s in signals)


def _infer_label(title: str, context: str) -> IncidentLabel:
    text = (title + " " + context).lower()
    for keywords, label in FAMILY_KEYWORDS_TO_LABEL:
        if any(kw in text for kw in keywords):
            return label
    return IncidentLabel.MIXED_SIGNAL_COMPROMISE


class HeuristicAgent:
    """Observation-only heuristic that mirrors what an LLM would reason."""

    def __init__(self) -> None:
        self.scanned = False
        self.inspected: set[str] = set()
        self.revoked: set[str] = set()
        self.approval_granted = False
        self.transferred: set[str] = set()
        self.suspicious_ids: list[str] = []
        self.benign_ids: set[str] = set()
        self.confirmed_malicious: set[str] = set()
        self.vault: str = ""
        self.threshold: float = 1000.0
        self.title: str = ""
        self.context: str = ""
        self.has_pending_threat = False

    def reset(self, obs: WalletRescueObservation) -> None:
        self.__init__()  # type: ignore[misc]
        self.vault = obs.policy_constraints.safe_vaults[0] if obs.policy_constraints.safe_vaults else ""
        self.threshold = obs.policy_constraints.high_value_threshold_usd
        self.title = obs.scenario_title
        self.context = obs.user_context

    def decide(self, obs: WalletRescueObservation) -> dict[str, Any]:
        if not self.scanned:
            self.scanned = True
            return {"kind": "scan_wallet"}

        if self.has_pending_threat:
            return self._urgent_path(obs)

        return self._investigation_path(obs)

    def _update_from_scan(self, obs: WalletRescueObservation) -> None:
        details = obs.last_tool_result.details
        if obs.last_tool_result.tool == "scan_wallet":
            suspicious = details.get("suspicious_approvals", [])
            suspicious_tx = details.get("suspicious_transactions", [])
            self.suspicious_ids = list(suspicious) + list(suspicious_tx)
            self.has_pending_threat = bool(suspicious_tx)

        if obs.last_tool_result.tool in ("inspect_transaction", "simulate_transaction"):
            tid = details.get("approval_id") or details.get("tx_id", "")
            if obs.last_tool_result.status.value == "warning":
                self.confirmed_malicious.add(tid)
            elif obs.last_tool_result.status.value == "success":
                target_type = details.get("target_type", "")
                if target_type == "approval":
                    self.benign_ids.add(tid)

        if obs.last_tool_result.tool == "revoke_approval":
            if "benign" in obs.last_tool_result.summary.lower():
                pass
            else:
                tid = obs.last_tool_result.summary.split()[-1].rstrip(".")
                self.revoked.add(tid)

        if obs.last_tool_result.tool == "request_secondary_approval":
            if obs.last_tool_result.status.value == "success":
                self.approval_granted = True

        if obs.last_tool_result.tool == "transfer_to_safe_vault":
            if obs.last_tool_result.status.value == "success":
                asset = details.get("asset", "")
                self.transferred.add(asset)
                self.approval_granted = False

    def _urgent_path(self, obs: WalletRescueObservation) -> dict[str, Any]:
        """When there are pending drainers, prioritise vault transfer."""
        if not self.approval_granted:
            assets = sorted(obs.wallet_snapshot, key=lambda a: a.usd_value, reverse=True)
            top = next((a for a in assets if a.amount > 0 and a.usd_value >= 5), None)
            if top and top.usd_value >= self.threshold:
                return {"kind": "request_secondary_approval"}

        assets = sorted(obs.wallet_snapshot, key=lambda a: a.usd_value, reverse=True)
        for asset in assets:
            if asset.amount > 0 and asset.usd_value >= 5 and asset.symbol not in self.transferred:
                if asset.usd_value >= self.threshold and not self.approval_granted:
                    return {"kind": "request_secondary_approval"}
                return {
                    "kind": "transfer_to_safe_vault",
                    "asset": asset.symbol,
                    "amount": asset.amount,
                    "destination": self.vault,
                }

        for ap in obs.active_approvals:
            if ap.status.value == "active" and ap.approval_id in self.confirmed_malicious:
                return {"kind": "revoke_approval", "target_id": ap.approval_id}
        for ap in obs.active_approvals:
            if ap.status.value == "active" and _looks_suspicious(ap.risk_hint) and ap.approval_id not in self.benign_ids:
                return {"kind": "revoke_approval", "target_id": ap.approval_id}

        return self._finish(obs)

    def _investigation_path(self, obs: WalletRescueObservation) -> dict[str, Any]:
        """When no urgent threat, investigate before acting."""
        for aid in self.suspicious_ids:
            if aid not in self.inspected:
                self.inspected.add(aid)
                return {"kind": "inspect_transaction", "target_id": aid}

        for ap in obs.active_approvals:
            if (
                ap.status.value == "active"
                and ap.approval_id not in self.inspected
                and _looks_suspicious(ap.risk_hint)
                and not _looks_benign(ap.risk_hint)
            ):
                self.inspected.add(ap.approval_id)
                return {"kind": "inspect_transaction", "target_id": ap.approval_id}

        for aid in self.confirmed_malicious:
            if aid not in self.revoked:
                for ap in obs.active_approvals:
                    if ap.approval_id == aid and ap.status.value == "active":
                        self.revoked.add(aid)
                        return {"kind": "revoke_approval", "target_id": aid}

        for ap in obs.active_approvals:
            if (
                ap.status.value == "active"
                and ap.approval_id not in self.revoked
                and ap.approval_id not in self.benign_ids
                and _looks_suspicious(ap.risk_hint)
            ):
                self.revoked.add(ap.approval_id)
                return {"kind": "revoke_approval", "target_id": ap.approval_id}

        assets = sorted(obs.wallet_snapshot, key=lambda a: a.usd_value, reverse=True)
        top = next((a for a in assets if a.amount > 0 and a.usd_value >= 5 and a.symbol not in self.transferred), None)
        if top:
            if top.usd_value >= self.threshold and not self.approval_granted:
                return {"kind": "request_secondary_approval"}
            self.transferred.add(top.symbol)
            return {
                "kind": "transfer_to_safe_vault",
                "asset": top.symbol,
                "amount": top.amount,
                "destination": self.vault,
            }

        return self._finish(obs)

    def _finish(self, obs: WalletRescueObservation) -> dict[str, Any]:
        label = _infer_label(self.title, self.context)
        return {
            "kind": "finish_incident",
            "message": (
                "The malicious threat was identified and contained. All revocable "
                "malicious approvals were revoked, funds were moved to the approved "
                "safe vault, and you should rotate to a fresh wallet immediately."
            ),
            "incident_label": label.value,
            "confidence": 0.92,
            "recommended_next_steps": [
                "Rotate to a new wallet and move any remaining trusted assets there.",
                "Monitor the attacker addresses and revoke any leftover sessions.",
            ],
            "rationale": (
                "The malicious entity was identified from inspection data and risk hints. "
                "Containment was prioritised to prevent further fund loss."
            ),
        }


# ---------------------------------------------------------------------------
# Action building / logging
# ---------------------------------------------------------------------------

def build_action(raw: dict[str, Any]) -> WalletRescueAction:
    cleaned = {k: v for k, v in raw.items() if v is not None}
    if "incident_label" in cleaned and isinstance(cleaned["incident_label"], str):
        cleaned["incident_label"] = IncidentLabel(cleaned["incident_label"])
    if "kind" in cleaned and isinstance(cleaned["kind"], str):
        cleaned["kind"] = ActionKind(cleaned["kind"])
    return WalletRescueAction(**cleaned)


def slim_action(action: WalletRescueAction) -> dict[str, Any]:
    d = action.model_dump(mode="json", exclude_none=True)
    d.pop("metadata", None)
    if not d.get("recommended_next_steps"):
        d.pop("recommended_next_steps", None)
    return d


# ---------------------------------------------------------------------------
# Task runner
# ---------------------------------------------------------------------------

def run_task(task: dict[str, Any]) -> float:
    env = WalletRescueEnvironment()
    obs = env.reset(seed=task["seed"])
    scenario_id = env.state.scenario_id

    emit("START", {
        "task_id": task["task_id"],
        "scenario_id": scenario_id,
        "seed": task["seed"],
        "timestamp": ts(),
    })

    heuristic = HeuristicAgent()
    heuristic.reset(obs)

    messages: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": obs_to_text(obs)},
    ]

    done = False
    step_num = 0
    cumulative_reward = 0.0

    while not done and step_num < 15:
        if USE_LLM:
            try:
                action_dict, raw_text = llm_decide(messages)
            except Exception:
                action_dict = heuristic.decide(obs)
                raw_text = json.dumps(action_dict)
        else:
            action_dict = heuristic.decide(obs)
            raw_text = json.dumps(action_dict)

        try:
            action = build_action(action_dict)
        except Exception:
            action = WalletRescueAction(kind=ActionKind.SCAN_WALLET)
            raw_text = '{"kind":"scan_wallet"}'

        obs = env.step(action)
        step_num += 1
        step_reward = round(max(0.001, min(0.999, obs.reward)), 4)
        cumulative_reward += step_reward
        done = obs.done

        emit("STEP", {
            "task_id": task["task_id"],
            "step": step_num,
            "action": slim_action(action),
            "reward": step_reward,
            "cumulative_reward": round(max(0.001, min(0.999, cumulative_reward)), 4),
            "done": done,
        })

        if USE_LLM:
            messages.append({"role": "assistant", "content": raw_text})
            messages.append({"role": "user", "content": obs_to_text(obs)})
        else:
            heuristic._update_from_scan(obs)

    score = round(max(0.001, min(0.999, env.state.score_breakdown.total)), 4)

    emit("END", {
        "task_id": task["task_id"],
        "scenario_id": scenario_id,
        "score": score,
        "steps": step_num,
        "timestamp": ts(),
    })

    return score


def main() -> int:
    if USE_LLM:
        print(f"[INFO] LLM mode: model={MODEL_NAME}", flush=True)
    else:
        print("[INFO] Heuristic mode (no LLM credentials detected)", flush=True)

    results: dict[str, float] = {}
    for task in TASKS:
        score = run_task(task)
        results[task["task_id"]] = score

    print(f"\n[SUMMARY] {json.dumps(results, indent=2)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
