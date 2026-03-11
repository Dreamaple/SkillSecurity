"""Ask confirmation prompter with configurable timeout."""

from __future__ import annotations

import sys
import threading
from typing import TextIO

from skillsecurity.config.defaults import DEFAULT_ASK_TIMEOUT_SECONDS


class AskPrompter:
    """Prompts user for confirmation with timeout and default-block behavior."""

    def __init__(
        self,
        timeout_seconds: int = DEFAULT_ASK_TIMEOUT_SECONDS,
        default_action: str = "block",
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._default = default_action
        self._input = input_stream or sys.stdin
        self._output = output_stream or sys.stderr

    def prompt(self, message: str = "", severity: str = "medium") -> bool:
        """Prompt user for y/n confirmation. Returns True if allowed, False if blocked."""
        if not self._input.isatty():
            return self._default == "allow"

        self._output.write(f"\n{message}\n")
        self._output.write(f"Timeout: {self._timeout}s (default: {self._default})\n")
        self._output.write("Allow this operation? [y/N] ")
        self._output.flush()

        result: list[str] = []
        event = threading.Event()

        def _read_input() -> None:
            try:
                line = self._input.readline().strip().lower()
                result.append(line)
            except EOFError:
                pass
            finally:
                event.set()

        reader = threading.Thread(target=_read_input, daemon=True)
        reader.start()

        event.wait(timeout=self._timeout)

        if not result:
            self._output.write(f"\nTimeout — applying default: {self._default}\n")
            return self._default == "allow"

        return result[0] in ("y", "yes")
