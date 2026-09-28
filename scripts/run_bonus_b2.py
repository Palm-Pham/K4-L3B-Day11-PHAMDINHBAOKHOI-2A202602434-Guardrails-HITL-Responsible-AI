"""Run selected B2 candidates against the unchanged Red Advance factory."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agents.guards_agent import create_red_agent_advance, detect_injection_strong, topic_filter_strong
from attacks.attacks import classify_attack_outcome
from attacks.bonus_b2 import B2_PROMPTS
from core.config import get_red_model, get_red_provider
from core.utils import chat_with_agent


async def main(ids: list[int] | None) -> None:
    path = ROOT / "outputs" / "bonus_b2_attempts.json"
    evidence = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
        "bonus_choice": "B2", "runs": []
    }
    run = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": get_red_provider(), "model": get_red_model(),
        "target_sha256": hashlib.sha256((ROOT / "src/agents/guards_agent.py").read_bytes()).hexdigest(),
        "results": [],
    }
    evidence["runs"].append(run)
    for attack in B2_PROMPTS:
        if ids and attack["id"] not in ids:
            continue
        prompt = attack["input"]
        row = dict(attack)
        row["offline_input_block"] = detect_injection_strong(prompt) or topic_filter_strong(prompt)
        try:
            # Fresh factory/session for each candidate; no altered target settings.
            agent, runner = create_red_agent_advance()
            response, _ = await chat_with_agent(agent, runner, prompt)
            row.update(classify_attack_outcome(prompt, response, target_name="red_advance"))
            row.update(response=response, error=None, target="red_advance")
        except Exception as exc:
            row.update(response="", error=f"{type(exc).__name__}: {exc}", leaked=False, layer="error")
        run["results"].append(row)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"B2 #{attack['id']}: leaked={row['leaked']} layer={row['layer']} error={bool(row['error'])}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ids", type=int, nargs="+")
    asyncio.run(main(parser.parse_args().ids))
