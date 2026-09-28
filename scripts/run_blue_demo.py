"""Local web demo for the existing Blue agent and its lab guardrails.

Run from the repository root with ``python scripts/run_blue_demo.py``.
Only the three files in demo/ and two JSON API routes are served.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agents.agent import create_blue_agent  # noqa: E402
from agents.security_boundary import contains_secret  # noqa: E402
from assignment.audit_log import AuditLogPlugin  # noqa: E402
from assignment.monitoring import MonitoringAlert  # noqa: E402
from assignment.pipeline import build_production_plugins  # noqa: E402
from core.config import get_blue_model, get_openrouter_api_key  # noqa: E402
from guardrails.output_guardrails import content_filter  # noqa: E402

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
MAX_BODY = 8_192
MAX_MESSAGE = 2_000


class BlueDemo:
    def __init__(self) -> None:
        self.plugins = build_production_plugins(use_llm_judge=False)
        self.agent, self.runner = create_blue_agent(self.plugins)
        # Bound a provider outage during a live presentation.
        self.runner.client_kwargs.update(timeout=30.0, max_retries=1)
        self.audit = AuditLogPlugin()
        self.monitor = MonitoringAlert()
        self.lock = threading.Lock()
        self.sequence = 0

    def status(self) -> dict:
        with self.lock:
            return {
                "configured": bool(get_openrouter_api_key()),
                "model": self.runner.model,
                "metrics": self.monitor.snapshot(),
            }

    def chat(self, message: str, user_id: str) -> dict:
        with self.lock:
            self.sequence += 1
            request_id = f"demo-{self.sequence:04d}"
            self.audit.record_input(user_id=user_id, text=message, request_id=request_id)
            rate, input_guard, output_guard = self.plugins
            before = (rate.blocked_count, input_guard.blocked_count,
                      output_guard.redacted_count, output_guard.blocked_count)
            layer = None
            model_called = False
            redacted = False
            try:
                block_message, checked_message = asyncio.run(
                    self.runner._run_input_plugins(message, user_id=user_id)
                )
                if block_message is not None:
                    reply = block_message
                else:
                    if not get_openrouter_api_key():
                        raise RuntimeError("Chưa cấu hình OPENROUTER_API_KEY trong .env.")
                    model_called = True
                    client = self.runner._client()
                    arguments = {
                        "messages": [
                            {"role": "system", "content": self.agent.instruction},
                            {"role": "user", "content": checked_message},
                        ],
                        "temperature": self.runner.temperature,
                    }
                    try:
                        completion = client.chat.completions.create(
                            model=self.runner.model, **arguments
                        )
                    except Exception as exc:
                        if getattr(exc, "status_code", None) != 404 or self.runner.model != get_blue_model():
                            raise
                        # OpenRouter may expose the same Liquid model only on
                        # its free endpoint. Keep the graded Blue config intact.
                        free_model = f"{get_blue_model()}:free"
                        completion = client.chat.completions.create(
                            model=free_model, **arguments
                        )
                        self.runner.model = free_model
                    reply = (completion.choices[0].message.content or "").strip()
                    reply = asyncio.run(self.runner._run_output_plugins(reply))
                after = (rate.blocked_count, input_guard.blocked_count,
                         output_guard.redacted_count, output_guard.blocked_count)
                if after[0] > before[0]:
                    layer = "rate_limiter"
                elif after[1] > before[1]:
                    layer = "input_guardrail"
                redacted = after[2] > before[2]
                if after[3] > before[3]:
                    layer = "output_guardrail"

                # Final response boundary: never return a known lab secret,
                # including DB hosts which the CP2 regex does not cover.
                if contains_secret(reply):
                    reply = "Nội dung này chứa dữ liệu được bảo vệ nên Blue không thể hiển thị."
                    layer = "response_boundary"
                else:
                    filtered = content_filter(reply)
                    if filtered["block"]:
                        reply = "I cannot provide that response. Please ask a banking question in English or Vietnamese."
                        layer = "response_boundary"
                    elif not filtered["safe"]:
                        reply = filtered["redacted"]
                        redacted = True

                blocked = layer is not None
                self.audit.record_output(
                    user_id=user_id, text=reply, blocked=blocked,
                    layer=layer, request_id=request_id,
                )
                self.monitor.total_requests += 1
                self.monitor.blocked_requests += int(blocked)
                self.monitor.rate_limit_hits += int(layer == "rate_limiter")
                self.monitor.input_guardrail_hits += int(layer == "input_guardrail")
                self.monitor.output_redactions += int(redacted)
                return {
                    "request_id": request_id,
                    "reply": reply,
                    "decision": "blocked" if blocked else "redacted" if redacted else "allowed",
                    "layer": layer,
                    "model_called": model_called,
                    "model": self.runner.model,
                    "redacted": redacted,
                    "metrics": self.monitor.snapshot(),
                }
            except Exception:
                self.audit.record_output(
                    user_id=user_id, text="Provider error", blocked=False,
                    layer="provider_error", request_id=request_id,
                )
                raise


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "BlueDemo/1.0"

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/status":
            self._json(200, self.server.demo.status())
            return
        if path not in STATIC:
            self.send_error(404)
            return
        filename, mime = STATIC[path]
        raw = (ROOT / "demo" / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        if self.path != "/api/chat":
            self.send_error(404)
            return
        expected_origin = f"http://127.0.0.1:{self.server.server_port}"
        if self.headers.get("Origin") != expected_origin:
            self._json(403, {"error": "Yêu cầu phải đến từ trang demo local."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Cần gửi JSON."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 1 or length > MAX_BODY:
            self._json(413, {"error": "Yêu cầu quá lớn hoặc rỗng."})
            return
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "JSON không hợp lệ."})
            return
        if not isinstance(data, dict):
            self._json(400, {"error": "Dữ liệu không hợp lệ."})
            return
        message = data.get("message")
        user_id = data.get("user_id")
        if not isinstance(message, str) or not message.strip() or len(message) > MAX_MESSAGE:
            self._json(400, {"error": f"Câu hỏi phải từ 1 đến {MAX_MESSAGE} ký tự."})
            return
        if not isinstance(user_id, str) or not (8 <= len(user_id) <= 64) or not user_id.isascii() or not all(c.isalnum() or c in "-_" for c in user_id):
            self._json(400, {"error": "Mã phiên không hợp lệ."})
            return
        try:
            self._json(200, self.server.demo.chat(message.strip(), user_id))
        except RuntimeError as exc:
            if "OPENROUTER_API_KEY" in str(exc):
                self._json(503, {"error": str(exc)})
            else:
                self._json(502, {"error": "Blue chưa nhận được phản hồi từ OpenRouter. Kiểm tra kết nối và key, rồi thử lại."})
        except Exception as exc:
            body = getattr(exc, "body", None)
            detail = body.get("message", "") if isinstance(body, dict) else ""
            detail = self.server.demo.audit._safe_text(str(detail))[:160]
            print(
                f"Blue request failed: {type(exc).__name__} "
                f"status={getattr(exc, 'status_code', 'none')} detail={detail}",
                file=sys.stderr,
                flush=True,
            )
            if getattr(exc, "status_code", None) == 404:
                self._json(502, {"error": "OpenRouter trả về 404 cho model Blue cố định. Kiểm tra quyền truy cập model trên tài khoản OpenRouter."})
            else:
                self._json(502, {"error": "Blue chưa nhận được phản hồi từ OpenRouter. Kiểm tra kết nối và key, rồi thử lại."})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Blue chatbot demo")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    server.demo = BlueDemo()
    print(f"Blue demo: http://127.0.0.1:{args.port}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
