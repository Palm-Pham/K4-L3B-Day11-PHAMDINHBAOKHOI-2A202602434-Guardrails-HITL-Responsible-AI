"""Retry only CP4 rows with provider errors, preserving successful evidence.

Run with the same RED_TEAM_PROVIDER and model used for attack_results.json.
This does not change a successful row or manufacture a model response.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agents.agent import create_red_agent_default
from agents.guards_agent import create_red_agent_advance
from attacks.attacks import (
    adversarial_prompts,
    run_attacks,
    save_attack_results,
    write_run_attack_json,
)
from core.config import get_red_model, get_red_provider


async def main() -> None:
    outputs = ROOT / "outputs"
    summary = json.loads((outputs / "attack_results.json").read_text(encoding="utf-8"))
    if (summary.get("llm_provider"), summary.get("llm_model")) != (
        get_red_provider(), get_red_model()
    ):
        raise ValueError("Current Red provider/model differs from existing CP4 artifacts")

    completed = {}
    for target, factory, filename in (
        ("red_default", create_red_agent_default, "unsafe_attack_result.json"),
        ("red_advance", create_red_agent_advance, "guards_attack_result.json"),
    ):
        rows = json.loads((outputs / filename).read_text(encoding="utf-8"))["results"]
        failed = [row for row in rows if row.get("error")]
        if failed:
            agent, runner = factory()
            retried = await run_attacks(
                agent,
                runner,
                prompts=[adversarial_prompts[row["id"] - 1] for row in failed],
                target_name=target,
                save_json=False,
            )
            succeeded = {row["id"]: row for row in retried if not row.get("error")}
            for row in rows:
                if row["id"] in succeeded:
                    row.update(succeeded[row["id"]])
        completed[target] = rows
        print(
            f"{target}: leaks={sum(bool(row.get('leaked')) for row in rows)}, "
            f"remaining_errors={sum(bool(row.get('error')) for row in rows)}"
        )

    write_run_attack_json(completed["red_default"], target_name="red_default")
    write_run_attack_json(completed["red_advance"], target_name="red_advance")
    save_attack_results(
        unsafe_results=completed["red_default"],
        guards_results=completed["red_advance"],
        ai_attacks=None,
    )


if __name__ == "__main__":
    asyncio.run(main())
