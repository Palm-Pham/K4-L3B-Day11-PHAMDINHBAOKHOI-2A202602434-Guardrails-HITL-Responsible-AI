"""Offline behavior checks for the CP3 pipeline and its artifacts."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.genai import types

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import (
    build_observability, build_production_plugins, is_egress_allowed,
    run_assignment_suite,
)
from assignment.rate_limiter import RateLimitPlugin
from core.openai_runtime import OpenAIAgent, OpenAIRunner


def test_rate_limit_sliding_window_per_user(monkeypatch):
    import assignment.rate_limiter as rate_module

    clock = [100.0]
    monkeypatch.setattr(rate_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    rate = RateLimitPlugin(max_requests=2, window_seconds=10)
    message = types.Content(role="user", parts=[types.Part.from_text(text="bank account")])

    async def request(user_id):
        return await rate.on_user_message_callback(
            invocation_context=SimpleNamespace(user_id=user_id), user_message=message
        )

    assert asyncio.run(request("a")) is None
    clock[0] = 101
    assert asyncio.run(request("a")) is None
    assert asyncio.run(request("a")) is not None
    assert asyncio.run(request("b")) is None
    clock[0] = 110
    assert asyncio.run(request("a")) is None
    assert rate.blocked_count == 1


def test_egress_requires_exact_https_host_and_clean_payload():
    safe = "approved bank transfer amount 500000"
    assert is_egress_allowed("https://api.vinbank.example/v1/transfers", safe)
    assert is_egress_allowed("https://cases.vinbank.example/case/1", safe)
    for destination in (
        "http://api.vinbank.example/v1/transfers",
        "https://api.vinbank.example.evil.test/v1/transfers",
        "https://evil.test@api.vinbank.example/v1/transfers",
        "https://api.vinbank.example:8443/v1/transfers",
        "https://api.vinbank.example/v1/transfers?password=admin123",
        "https://evil.test/collect",
    ):
        assert not is_egress_allowed(destination, safe)
    for payload in (
        "admin password is admin123", "API key sk-vinbank-secret-2024",
        "db.vinbank.internal:5432", "Call 0901234567", "Email lan@example.com",
        "bank\u200b account details",
    ):
        assert not is_egress_allowed("https://api.vinbank.example/v1/transfers", payload)


def test_audit_redacts_and_monitoring_exports(tmp_path):
    audit = AuditLogPlugin()
    audit.record_input(user_id="a", text="My bank phone is 0901234567", request_id="r1")
    audit.record_output(user_id="a", text="password=admin123", blocked=True,
                        layer="input_guardrail", request_id="r1")
    audit_path = audit.export_json(str(tmp_path / "audit_log.json"))
    log = json.loads(audit_path.read_text(encoding="utf-8"))[0]
    assert log["input"] == "My bank phone is [REDACTED]"
    assert "admin123" not in json.dumps(log)
    assert log["blocked"] and log["layer"] == "input_guardrail"
    assert log["latency_ms"] >= 0

    monitor = MonitoringAlert(block_rate_threshold=0.5, rate_limit_hit_threshold=1)
    monitor.total_requests = 2
    monitor.blocked_requests = 2
    monitor.rate_limit_hits = 1
    assert len(monitor.check_metrics()) == 2
    assert len(monitor.check_metrics()) == 2
    metrics = json.loads(monitor.export_json(str(tmp_path / "metrics.json")).read_text(
        encoding="utf-8"
    ))
    assert metrics["block_rate"] == 1.0
    assert metrics["rate_limit_hits"] == 1


@pytest.mark.parametrize("live_model", [False, True])
def test_suite_runs_ordered_plugins_and_writes_contract_artifacts(tmp_path, monkeypatch, live_model):
    import agents.agent as agent_module

    plugins = build_production_plugins(max_requests=2, window_seconds=60)
    assert [plugin.name for plugin in plugins] == [
        "rate_limiter", "input_guardrail", "output_guardrail"
    ]
    audit, monitor = build_observability()

    def create_offline_blue(active_plugins):
        runner = OpenAIRunner(app_name="cp3", model="offline", plugins=active_plugins)
        runner._client = lambda: SimpleNamespace(chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kwargs: SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(
                    content="VinBank can help with your banking question."
                ))]
            ))
        ))
        if not live_model:
            runner._client = lambda: pytest.fail("Policy-only suite called the model")
        return OpenAIAgent(name="blue", instruction="Banking only"), runner

    monkeypatch.setattr(agent_module, "create_blue_agent", create_offline_blue)
    outputs = tmp_path / "outputs"
    result = asyncio.run(run_assignment_suite({
        "plugins": plugins, "audit": audit, "monitor": monitor, "output_dir": outputs,
        "live_model": live_model,
    }))
    assert result["execution_mode"] == ("live" if live_model else "policy-only")
    assert all(item["model_executed"] is live_model for item in result["safe_queries"])
    assert len(result["safe_queries"]) >= 5
    assert all(not item["blocked"] for item in result["safe_queries"])
    assert sum(item["blocked"] for item in result["attack_queries"]) >= 5
    assert len(result["edge_cases"]) >= 3
    assert all(case["matches_expected"] for case in result["output_checks"])
    assert result["egress_checks"] == [
        {"id": "authorized_clean", "allowed": True},
        {"id": "foreign_host", "allowed": False},
        {"id": "sensitive_payload", "allowed": False},
    ]
    assert result["rate_limit"]["blocked"] >= 1
    assert result["rate_limit"]["sent"] == sum(
        result["rate_limit"][key] for key in ("passed", "blocked")
    )
    assert {path.name for path in outputs.iterdir()} == {
        "results.json", "audit_log.json", "metrics.json"
    }
    assert len(json.loads((outputs / "audit_log.json").read_text(encoding="utf-8"))) == (
        5 + 7 + 3 + result["rate_limit"]["sent"]
    )
