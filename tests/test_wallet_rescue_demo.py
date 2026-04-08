"""Tests for demo artifact generation."""

from __future__ import annotations

import json

from wallet_rescue_ops.demo import generate_demo_artifacts


def test_demo_artifact_generation(tmp_path) -> None:
    success_path, failure_path = generate_demo_artifacts(tmp_path)

    success = json.loads(success_path.read_text(encoding="utf-8"))
    failure = json.loads(failure_path.read_text(encoding="utf-8"))

    assert success["scenario_id"] == "airdrop-mirage"
    assert failure["scenario_id"] == "airdrop-mirage"
    assert success["score_breakdown"]["total"] > failure["score_breakdown"]["total"]
    assert success["trace"][-1]["done"] is True
    assert failure["trace"][-1]["done"] is True
