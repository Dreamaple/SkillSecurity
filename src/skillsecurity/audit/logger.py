"""Async JSONL log writer with Queue + daemon thread."""

from __future__ import annotations

import atexit
import json
import logging
import queue
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillsecurity.audit.redactor import Redactor

logger = logging.getLogger("skillsecurity.audit")


class AuditLogger:
    def __init__(
        self,
        output_path: str | Path = "./logs/skillsecurity-audit.jsonl",
        redactor: Redactor | None = None,
    ) -> None:
        self._path = Path(output_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._redactor = redactor or Redactor()
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._counter = 0
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._write_loop, daemon=True)
        self._worker.start()
        atexit.register(self.flush)

    def log(
        self,
        event_type: str,
        request: dict[str, Any] | None = None,
        decision: dict[str, Any] | None = None,
        **extra: Any,
    ) -> None:
        with self._lock:
            self._counter += 1
            entry_id = f"{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{self._counter:06d}"
        entry: dict[str, Any] = {
            "id": entry_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
        }
        if request:
            entry["request"] = self._redactor.redact_dict(request)
        if decision:
            entry["decision"] = decision
        entry.update(extra)
        self._queue.put(entry)

    def flush(self) -> None:
        self._queue.put(None)
        self._worker.join(timeout=5)

    def _write_loop(self) -> None:
        while True:
            try:
                entry = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            if entry is None:
                self._flush_remaining()
                break
            self._write_entry(entry)

    def _flush_remaining(self) -> None:
        while not self._queue.empty():
            try:
                entry = self._queue.get_nowait()
                if entry is not None:
                    self._write_entry(entry)
            except queue.Empty:
                break

    def _write_entry(self, entry: dict[str, Any]) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            logger.exception("Failed to write audit log entry")
