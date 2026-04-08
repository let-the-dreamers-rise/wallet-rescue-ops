"""FastAPI app for Wallet Rescue Ops."""

from fastapi import HTTPException

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

