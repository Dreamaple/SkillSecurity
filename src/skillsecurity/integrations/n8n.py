"""n8n integration — provides a webhook middleware for n8n custom code nodes.

n8n runs as a separate Node.js process, so Python-level monkey-patching isn't applicable.
Instead, this adapter provides:
  1. A FastAPI/Flask middleware that n8n HTTP Request nodes can call as a security gateway.
  2. A CLI command to run the gateway server.

Usage:
    # Option 1: In your Python code
    from skillsecurity.integrations import install
    install("n8n", host="0.0.0.0", port=9090)

    # Option 2: CLI
    skillsecurity serve-n8n --port 9090

    # In n8n: Use HTTP Request node to POST to http://localhost:9090/check
    # before executing the actual tool node.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from skillsecurity.integrations._base import _get_or_create_guard

_server_thread: threading.Thread | None = None
_shutdown_event: threading.Event | None = None
_guard: Any = None


def install(**kwargs: Any) -> None:
    """Start an HTTP gateway server that n8n can query for security checks.

    Keyword Args:
        host: Bind address (default "127.0.0.1").
        port: Port number (default 9090).
        guard: Pre-configured SkillGuard instance.
        policy_file / policy / config: Passed to SkillGuard if guard is not provided.
    """
    global _guard, _server_thread, _shutdown_event

    _guard = _get_or_create_guard(**kwargs)
    host = kwargs.get("host", "127.0.0.1")
    port = kwargs.get("port", 9090)

    _shutdown_event = threading.Event()

    def _run_server() -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        guard = _guard

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/check":
                    self.send_response(404)
                    self.end_headers()
                    return

                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    tool_call = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Invalid JSON"}')
                    return

                decision = guard.check(tool_call)
                resp = json.dumps(decision.to_dict(), ensure_ascii=False)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp.encode("utf-8"))

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = HTTPServer((host, port), Handler)
        server.timeout = 1.0
        while not _shutdown_event.is_set():  # type: ignore[union-attr]
            server.handle_request()
        server.server_close()

    _server_thread = threading.Thread(target=_run_server, daemon=True)
    _server_thread.start()


def uninstall() -> None:
    """Stop the n8n gateway server."""
    global _guard, _server_thread, _shutdown_event
    if _shutdown_event is not None:
        _shutdown_event.set()
    if _server_thread is not None:
        _server_thread.join(timeout=5)
    _server_thread = None
    _shutdown_event = None
    _guard = None
