"""Client/server smoke test for Wallet Rescue Ops."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import Generator

import requests

from wallet_rescue_ops import WalletRescueAction, WalletRescueOpsEnv


def find_free_port() -> int:
    """Pick an available localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def run_server(port: int) -> Generator[str, None, None]:
    """Run the FastAPI app in a subprocess for a smoke test."""
    env = os.environ.copy()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "wallet_rescue_ops.server.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    base_url = f"http://127.0.0.1:{port}"
    try:
        started = False
        for _ in range(40):
            try:
                response = requests.get(f"{base_url}/health", timeout=1)
                if response.status_code == 200:
                    started = True
                    break
            except requests.exceptions.ConnectionError:
                time.sleep(0.25)
        if not started:
            stderr = process.stderr.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Server did not start. stderr:\n{stderr}")

        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_client_server_smoke() -> None:
    port = find_free_port()
    with run_server(port) as base_url:
        with WalletRescueOpsEnv(base_url=base_url).sync() as client:
            reset_result = client.reset(seed=0)
            assert reset_result.observation.scenario_title == "Airdrop Mirage"

            step_result = client.step(WalletRescueAction(kind="scan_wallet"))
            assert "suspicious approval" in step_result.observation.last_tool_result.summary

            state = client.state()
            assert state.scenario_id == "airdrop-mirage"
            assert state.step_count == 1
