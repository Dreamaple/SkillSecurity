"""Dashboard HTTP server — zero external dependencies, pure stdlib."""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from skillsecurity.dashboard.api import DashboardAPI

logger = logging.getLogger("skillsecurity.dashboard")

_STATIC_DIR = Path(__file__).parent / "static"


class _DashboardHandler(BaseHTTPRequestHandler):
    api: DashboardAPI

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_file(_STATIC_DIR / "index.html", "text/html")
        elif path == "/api/stats":
            self._json_response(self.api.get_stats())
        elif path == "/api/logs":
            limit = int(params.get("limit", ["50"])[0])
            action = params.get("action", [None])[0]
            self._json_response(self.api.get_recent_logs(limit=limit, action=action))
        elif path == "/api/frameworks":
            self._json_response(self.api.get_frameworks())
        elif path == "/api/config":
            self._json_response(self.api.get_config())
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        length = int(self.headers.get("Content-Length", 0))
        body: dict[str, Any] = {}
        if length > 0:
            raw = self.rfile.read(length)
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                body = json.loads(raw)

        if path == "/api/protect":
            fw = body.get("framework", "")
            policy = body.get("policy")
            result = self.api.protect_framework(fw, policy)
            self._json_response(result)
        elif path == "/api/unprotect":
            fw = body.get("framework", "")
            result = self.api.unprotect_framework(fw)
            self._json_response(result)
        elif path == "/api/scan":
            skill_path = body.get("path", "")
            result = self.api.scan_skill(skill_path)
            self._json_response(result)
        else:
            self.send_error(404)

    def _json_response(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, filepath: Path, content_type: str) -> None:
        if not filepath.exists():
            self.send_error(404)
            return
        content = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 9099,
    log_path: str = "./logs/skillsecurity-audit.jsonl",
    open_browser: bool = True,
) -> None:
    """Start the dashboard server (blocking)."""
    api = DashboardAPI(log_path=log_path)

    handler_class = type("Handler", (_DashboardHandler,), {"api": api})
    server = HTTPServer((host, port), handler_class)

    url = f"http://{host}:{port}"
    print(f"\n  SkillSecurity Dashboard running at {url}")
    print("  Press Ctrl+C to stop.\n")

    if open_browser:
        threading.Timer(0.5, _open_browser, args=[url]).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
    finally:
        server.server_close()


def _open_browser(url: str) -> None:
    import webbrowser

    webbrowser.open(url)
