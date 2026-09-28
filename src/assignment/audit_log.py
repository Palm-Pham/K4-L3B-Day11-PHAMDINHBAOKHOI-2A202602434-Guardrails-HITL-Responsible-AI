"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.security_boundary import contains_secret
from guardrails.output_guardrails import content_filter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[float, str, str, str]] = {}

    @staticmethod
    def _safe_text(text: str) -> str:
        cleaned = content_filter(text)["redacted"]
        return "[REDACTED]" if contains_secret(cleaned) else cleaned

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Start a request record; retain only sanitized text."""
        key = request_id or user_id
        self._open[key] = (time.monotonic(), utc_now_iso(), user_id, self._safe_text(text))

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish a request record with its decision and elapsed time."""
        key = request_id or user_id
        started = self._open.pop(key, None)
        start_clock, started_at, recorded_user, input_text = started or (
            time.monotonic(), utc_now_iso(), user_id, ""
        )
        self.logs.append({
            "request_id": key,
            "user_id": recorded_user,
            "timestamp": started_at,
            "completed_at": utc_now_iso(),
            "input": input_text,
            "output": self._safe_text(text),
            "event": "guardrail_block" if blocked else "response",
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((time.monotonic() - start_clock) * 1000, 2),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
