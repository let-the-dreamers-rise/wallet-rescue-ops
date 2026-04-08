"""FastAPI app for Wallet Rescue Ops."""

from fastapi import HTTPException
from fastapi.responses import HTMLResponse

try:
    from ..models import WalletRescueAction, WalletRescueObservation
except ImportError:
    from models import WalletRescueAction, WalletRescueObservation  # type: ignore[no-redef]

try:
    from .wallet_rescue_environment import WalletRescueEnvironment
except ImportError:
    from server.wallet_rescue_environment import WalletRescueEnvironment  # type: ignore[no-redef]

from openenv.core.env_server import create_app

app = create_app(
    WalletRescueEnvironment,
    WalletRescueAction,
    WalletRescueObservation,
    env_name="wallet_rescue_ops",
    max_concurrent_envs=8,
)


TASKS = [
    {
        "id": "trivial_rescue",
        "name": "Trivial: Already Drained Once",
        "description": (
            "A first drain already happened. One malicious approval, no pending "
            "drainers, no look-alikes. Revoke, vault, and close."
        ),
        "difficulty": "trivial",
        "seed": 9,
        "max_steps": 7,
    },
    {
        "id": "easy_rescue",
        "name": "Easy: Fake Airdrop Containment",
        "description": (
            "A single malicious fake-airdrop approval targets the USDC balance. "
            "Identify it, revoke it, vault the funds, and close the incident."
        ),
        "difficulty": "easy",
        "seed": 0,
        "max_steps": 7,
    },
    {
        "id": "medium_rescue",
        "name": "Medium: Mixed Signal Triage",
        "description": (
            "Two nearly identical approval names -- one malicious, one benign. "
            "Correctly discriminate, revoke only the threat, and protect the wallet."
        ),
        "difficulty": "medium",
        "seed": 6,
        "max_steps": 8,
    },
    {
        "id": "hard_rescue",
        "name": "Hard: Post-Compromise Salvage with Pending Drainer",
        "description": (
            "Funds already partially drained. A pending malicious transfer races "
            "the clock. Salvage the remaining balance under time pressure."
        ),
        "difficulty": "hard",
        "seed": 10,
        "max_steps": 7,
    },
    {
        "id": "expert_rescue",
        "name": "Expert: Market Maker or Drainer",
        "description": (
            "Two approvals differ by one character (Market-Makr vs Market-Maker). "
            "A queued transaction mirrors the spoof. Revoking the wrong one triggers "
            "a harsh false-positive penalty. Must inspect before acting."
        ),
        "difficulty": "expert",
        "seed": 8,
        "max_steps": 8,
    },
]


@app.get("/", response_class=HTMLResponse)
def landing_page() -> str:
    """Human-friendly landing page for judges and visitors."""
    rows = "".join(
        f"<tr><td><code>{t['id']}</code></td><td>{t['difficulty']}</td>"
        f"<td>{t['seed']}</td><td>{t['description']}</td></tr>"
        for t in TASKS
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Wallet Rescue Ops — OpenEnv Environment</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;
        display:flex;justify-content:center;padding:2rem}}
  .card{{max-width:860px;width:100%;background:#161b22;border:1px solid #30363d;
         border-radius:12px;padding:2.5rem}}
  h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:.3rem}}
  .sub{{color:#8b949e;margin-bottom:1.5rem}}
  h2{{color:#c9d1d9;font-size:1.1rem;margin:1.5rem 0 .5rem;border-bottom:1px solid #21262d;padding-bottom:.4rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-top:.5rem}}
  th,td{{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #21262d}}
  th{{color:#8b949e;font-weight:600}}
  code{{background:#1f2937;padding:.15rem .4rem;border-radius:4px;font-size:.82rem;color:#7ee787}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .badge{{display:inline-block;padding:.2rem .6rem;border-radius:12px;font-size:.75rem;font-weight:600}}
  .live{{background:#238636;color:#fff}}
  .endpoints li{{margin:.3rem 0}}
  .footer{{margin-top:1.5rem;color:#484f58;font-size:.8rem;text-align:center}}
</style></head><body><div class="card">
  <h1>Wallet Rescue Ops v2</h1>
  <p class="sub">OpenEnv incident-response benchmark for compromised crypto wallets
    &nbsp;<span class="badge live">RUNNING</span></p>

  <h2>API Endpoints</h2>
  <ul class="endpoints">
    <li><a href="/health"><code>GET /health</code></a> — Healthcheck</li>
    <li><a href="/tasks"><code>GET /tasks</code></a> — List all 5 graded tasks</li>
    <li><code>WS /ws</code> — WebSocket: <code>reset(seed)</code>, <code>step(action)</code>, <code>state()</code></li>
    <li><a href="/docs"><code>GET /docs</code></a> — Interactive Swagger UI</li>
  </ul>

  <h2>Tasks</h2>
  <table><thead><tr><th>ID</th><th>Difficulty</th><th>Seed</th><th>Description</th></tr></thead>
  <tbody>{rows}</tbody></table>

  <h2>Baseline Scores (heuristic, no LLM)</h2>
  <table><thead><tr><th>Task</th><th>Score</th><th>Steps</th></tr></thead><tbody>
    <tr><td>trivial_rescue</td><td><strong>0.96</strong></td><td>7</td></tr>
    <tr><td>easy_rescue</td><td><strong>0.98</strong></td><td>7</td></tr>
    <tr><td>medium_rescue</td><td><strong>0.98</strong></td><td>8</td></tr>
    <tr><td>hard_rescue</td><td><strong>0.99</strong></td><td>6</td></tr>
    <tr><td>expert_rescue</td><td><strong>0.77</strong></td><td>7</td></tr>
  </tbody></table>

  <p class="footer">Built for the Meta PyTorch OpenEnv Hackathon 2026 &middot;
    <a href="https://github.com/meta-pytorch/OpenEnv">OpenEnv Framework</a></p>
</div></body></html>"""


@app.get("/tasks")
def list_tasks() -> list[dict]:
    """Enumerate graded tasks for automated evaluation."""
    return TASKS


@app.get("/tasks/{task_id}")
def get_task(task_id: str) -> dict:
    """Get a specific task definition."""
    for task in TASKS:
        if task["id"] == task_id:
            return task
    raise HTTPException(status_code=404, detail=f"Unknown task_id: {task_id}")


def main() -> None:
    """Run the FastAPI server directly."""
    import os

    import uvicorn

    port = int(os.environ.get("PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()

