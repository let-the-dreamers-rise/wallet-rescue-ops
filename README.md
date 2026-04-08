---
title: Wallet Rescue Ops
emoji: "🛡️"
colorFrom: red
colorTo: orange
sdk: docker
app_port: 7860
pinned: true
tags:
  - openenv
---

# Wallet Rescue Ops v2

Wallet Rescue Ops is an OpenEnv incident-response benchmark for compromised crypto wallets. An agent investigates suspicious approvals and queued transfers, contains the incident under policy constraints, moves funds to a safe vault, and closes the case with a user-facing explanation.

## Why This Matters

Wallet drainers stole over **$1.7 billion** from crypto users in 2023-2024 (Chainalysis). Current defenses are static classifiers or manual playbooks. Neither handles the *sequential* decision-making required during an active incident: which approvals to revoke, whether to vault funds before or after investigation, how to avoid false positives on look-alike entities, and how to communicate with the user under time pressure. This environment turns that real-world problem into a reproducible RL benchmark.

## 60-Second Overview

- **Problem**: wallet drainers, fake airdrops, spoofed support flows, and queued malicious transfers are high-stakes, sequential, and costly to mis-handle.
- **Agent task**: inspect, simulate, revoke, escalate, transfer, and explain -- 8 action types with inter-dependencies.
- **Why this fits OpenEnv**: each action changes the world, some threats execute on a timer, and the best policy is not a one-shot classification.
- **Offline only**: no live wallets, no browser automation, no private keys, no chain calls.

## Project Structure

```
metapytorch/
├── Dockerfile              # Root Dockerfile for HF Spaces (port 7860)
├── README.md               # This file (HF Space metadata in YAML frontmatter)
├── openenv.yaml            # OpenEnv manifest: 5 graded tasks
├── inference.py            # Baseline inference script (LLM + heuristic fallback)
├── requirements.txt        # Pinned dependencies
├── pyproject.toml          # Build config, entry points, test config
├── wallet_rescue_ops/
│   ├── __init__.py         # Public API re-exports
│   ├── models.py           # Pydantic Action, Observation, State models
│   ├── episodes.py         # 12 deterministic scenario definitions
│   ├── client.py           # WebSocket EnvClient wrapper
│   ├── demo.py             # Good/bad trajectory generator
│   └── server/
│       ├── __init__.py
│       ├── app.py          # FastAPI app, /tasks endpoint, create_app()
│       └── wallet_rescue_environment.py  # Core env: reset/step/state + grader
└── tests/
    ├── test_wallet_rescue_environment.py  # Core env unit tests
    ├── test_wallet_rescue_client_server.py # HTTP smoke test
    ├── test_wallet_rescue_demo.py          # Demo artifact test
    └── test_tasks_and_graders.py           # Tasks, graders, score normalization,
                                            # difficulty progression, inference script
```

## Episode Families

- `fake_airdrop`: malicious approval introduced by a spoofed claim flow.
- `pending_drainer`: a queued malicious transfer races against the agent.
- `mixed_signal`: benign and malicious entities look confusingly similar.
- `post_compromise`: some value is already gone; the agent must salvage the rest.

The environment ships 12 deterministic scenarios, reachable via `seed % 12` or `reset(..., scenario_id="...")`.

## Public Interfaces

- `WalletRescueAction`
  - `kind`: `scan_wallet`, `inspect_transaction`, `simulate_transaction`, `revoke_approval`, `transfer_to_safe_vault`, `request_secondary_approval`, `message_user`, `finish_incident`
  - extra fields depend on the action: `target_id`, `asset`, `amount`, `destination`, `message`, `incident_label`, `confidence`, `recommended_next_steps`, `rationale`
- `WalletRescueObservation`
  - `user_context`, `wallet_snapshot`, `pending_transactions`, `active_approvals`, `policy_constraints`, `last_tool_result`, `remaining_steps`
  - final observations also expose `score_breakdown`
- `WalletRescueState`
  - hidden/reference state for grading: malicious entities, revoked approvals, neutralized transactions, losses, policy flags, and reference facts

## Reward Design

| Component | Max | Notes |
| --- | ---: | --- |
| Funds preserved | 40 | Based on value actually moved into the approved safe vault |
| Malicious approvals revoked | 20 | Full points only when all malicious approvals are revoked |
| Policy compliance | 15 | Requires compliant high-value transfer behavior |
| False-positive avoidance | 10 | Awarded only when the episode closes without benign revokes |
| Efficiency | 10 | Rewards closing near the ideal action count |
| Closure quality | 5 | Programmatic check of the final explanation fields |
| Penalties | negative | Wrong destination, missing approval, false positives, executed drainers, invalid actions, unresolved threats |

## LLM-Scoring Optimization

The environment reward itself is deterministic. To make the benchmark judge-friendly for mixed grading:

- every episode carries hidden `reference_facts`
- `finish_incident` requires:
  - a final user message
  - a canonical incident label
  - a confidence value
  - recommended next steps
  - a short rationale
- the closure score checks whether the final explanation:
  - identifies the malicious incident correctly
  - mentions containment actions
  - communicates follow-up safety steps
  - includes at least two concrete next steps

Suggested human/LLM rubric:

- `accuracy`: did the agent identify the real malicious entity and avoid hallucinating benign ones?
- `clarity`: does the final note explain what happened in plain language?
- `user trust`: does the response sound calm, specific, and operationally useful?
- `safety of next steps`: are the follow-ups actually protective, like rotating wallets and monitoring addresses?

## Why RL, Not Rules

- The environment is sequential: threats can trigger after a few steps.
- Some suspicious-looking entities are benign, so aggressive blocking can lower score.
- Correct action order matters: a large vault transfer without secondary approval is a failure.
- A static scam classifier cannot model the tradeoff between investigation, containment, and communication.

## Good Trajectory

Example from `airdrop-mirage`:

1. `scan_wallet`
2. `inspect_transaction(target_id="apr-air-001")`
3. `revoke_approval(target_id="apr-air-001")`
4. `request_secondary_approval`
5. `transfer_to_safe_vault(asset="USDC", amount=1200, destination="vault://cold-alpha")`
6. `finish_incident(...)`

Expected outcome:

- malicious approval revoked before trigger
- funds moved to the approved vault
- no false positives
- high final score with a clear user explanation

## Bad Trajectory

Example failure from `airdrop-mirage`:

1. `scan_wallet`
2. `transfer_to_safe_vault(asset="USDC", amount=1200, destination="vault://cold-alpha")`
3. `finish_incident(...)`

Expected outcome:

- transfer is blocked because secondary approval was not requested
- malicious approval remains live
- forced settlement drains remaining funds on close
- large policy and unresolved-threat penalties

## Demo Story

Pitch the benchmark like this:

> "This is not a crypto scam classifier. It is a wallet incident-response environment. The same wallet can end in two very different outcomes depending on whether the agent investigates correctly, follows policy, and moves funds before the drainer fires."

For a 2-minute demo:

1. show `airdrop-mirage` and run the good path
2. reset the same scenario and run the bad path
3. compare the final `score_breakdown`

You can generate both trajectories automatically:

```bash
python -m wallet_rescue_ops.demo
```

That writes:

- `outputs/evals/success_trajectory.json`
- `outputs/evals/failure_trajectory.json`

## Tasks (OpenEnv Spec)

Five graded tasks with increasing difficulty. Each maps to a deterministic
scenario via `seed`. Scores are normalised to 0.0-1.0 (internal total / 100,
clamped). The `/tasks` endpoint enumerates all tasks programmatically.

| Task ID | Difficulty | Seed | Scenario | Key Challenge |
|---|---|---|---|---|
| `trivial_rescue` | Trivial | 9 | Already Drained Once | Single approval, no drainers, no look-alikes |
| `easy_rescue` | Easy | 0 | Airdrop Mirage | One malicious + one benign approval |
| `medium_rescue` | Medium | 6 | Mixed Approval Maze | Confusingly similar names (Jup1ter vs Jupiter) |
| `hard_rescue` | Hard | 10 | Partial SOL Sweep | Post-compromise + pending drainer at step 3 |
| `expert_rescue` | Expert | 8 | Market Maker or Drainer | Single-character name diff; false-positive trap |

## Baseline Scores

Observation-only heuristic agent (no LLM, no internal-state access):

| Task | Score | Steps | Notes |
|---|---|---|---|
| `trivial_rescue` | **0.96** | 7 | Near-perfect; slight efficiency cost from inspection |
| `easy_rescue` | **0.98** | 7 | Handles single threat cleanly |
| `medium_rescue` | **0.98** | 8 | Correct discrimination of look-alikes |
| `hard_rescue` | **0.99** | 6 | Urgent vault-first path beats the drainer |
| `expert_rescue` | **0.77** | 7 | Revokes benign approval (false positive -10), wrong label |

The expert task demonstrates that a simple heuristic fails when two approvals
differ by one character (`Market-Makr` vs `Market-Maker`). An LLM agent that
inspects before revoking would avoid the false-positive penalty and score higher.

## Environment Variables

The following variables must be defined before running `inference.py`:

| Variable | Purpose |
|---|---|
| `API_BASE_URL` | OpenAI-compatible API endpoint (e.g. `https://api.openai.com/v1`) |
| `MODEL_NAME` | Model identifier (e.g. `gpt-4o-mini`) |
| `HF_TOKEN` | Hugging Face / API key used as the bearer token |
| `OPENAI_API_KEY` | Alternative to `HF_TOKEN` (either works) |

## Quickstart

```bash
pip install -e .[dev]
```

### Run the server

```bash
uvicorn wallet_rescue_ops.server.app:app --host 127.0.0.1 --port 7860
```

Built-in OpenEnv web UI:

```bash
set ENABLE_WEB_INTERFACE=true
uvicorn wallet_rescue_ops.server.app:app --host 127.0.0.1 --port 7860
```

Then open `http://127.0.0.1:7860/web`.

### Run the baseline inference script

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export HF_TOKEN="sk-..."
python inference.py
```

Without credentials the script falls back to a deterministic heuristic agent:

```bash
python inference.py
```

### Client example

```python
from wallet_rescue_ops import IncidentLabel, WalletRescueAction, WalletRescueOpsEnv

with WalletRescueOpsEnv(base_url="http://127.0.0.1:7860").sync() as env:
    env.reset(seed=0)
    env.step(WalletRescueAction(kind="scan_wallet"))
    env.step(WalletRescueAction(kind="revoke_approval", target_id="apr-air-001"))
```

## Docker

```bash
docker build -t wallet-rescue-ops .
docker run -p 7860:7860 wallet-rescue-ops
```

## Local Validation

```bash
python -m pytest -v
```

19 tests cover: environment determinism, all 12 scenarios reachable, reward correctness, false-positive penalties, policy compliance, score normalization, task endpoint, difficulty progression, inference script execution, and client/server smoke.

## Pre-Submission Checklist

- [x] HF Space deploys (Dockerfile at root, port 7860, `tags: [openenv]`)
- [x] `reset()` returns 200 and responds correctly
- [x] `openenv.yaml` with typed models, `step()`/`reset()`/`state()` endpoints
- [x] Dockerfile builds without errors
- [x] `inference.py` in root, uses OpenAI Client, emits `[START]`/`[STEP]`/`[END]` logs
- [x] 5 tasks (trivial/easy/medium/hard/expert) with scores in 0.0-1.0 range
- [x] `API_BASE_URL`, `MODEL_NAME`, `HF_TOKEN` / `OPENAI_API_KEY` defined and used
- [x] Baseline scores documented in README
- [x] 19 passing unit tests (`python -m pytest`)
- [x] Runtime < 20 min, runs on vcpu=2 / 8 GB (heuristic completes in < 1 s)
