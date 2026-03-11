"""File system watcher for policy hot-reload with debounce."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from skillsecurity.engine.policy import PolicyEngine, PolicyLoadError

logger = logging.getLogger("skillsecurity.watcher")


class _PolicyReloadHandler(FileSystemEventHandler):
    def __init__(
        self, engine: PolicyEngine, policy_path: Path, debounce_seconds: float = 1.0
    ) -> None:
        self._engine = engine
        self._policy_path = policy_path.resolve()
        self._debounce = debounce_seconds
        self._last_reload: float = 0
        self._lock = threading.Lock()

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return

        modified_path = Path(event.src_path).resolve()
        if modified_path != self._policy_path:
            return

        now = time.monotonic()
        with self._lock:
            if now - self._last_reload < self._debounce:
                return
            self._last_reload = now

        self._reload()

    def _reload(self) -> None:
        try:
            self._engine.load_file(self._policy_path)
            logger.info("Policy reloaded successfully from %s", self._policy_path)
        except PolicyLoadError as e:
            logger.warning("Policy reload failed, keeping old policy: %s", e)
        except Exception:
            logger.exception("Unexpected error during policy reload")


class PolicyWatcher:
    """Watches a policy file for changes and hot-reloads the engine."""

    def __init__(
        self,
        engine: PolicyEngine,
        policy_path: str | Path,
        debounce_seconds: float = 1.0,
    ) -> None:
        self._policy_path = Path(policy_path).resolve()
        self._handler = _PolicyReloadHandler(engine, self._policy_path, debounce_seconds)
        self._observer = Observer()
        self._observer.schedule(
            self._handler,
            str(self._policy_path.parent),
            recursive=False,
        )

    def start(self) -> None:
        self._observer.daemon = True
        self._observer.start()
        logger.info("Policy watcher started for %s", self._policy_path)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        logger.info("Policy watcher stopped")
