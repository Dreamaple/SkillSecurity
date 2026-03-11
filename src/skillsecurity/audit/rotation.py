"""Log file rotation by size and retention by age."""

from __future__ import annotations

import time
from pathlib import Path


class LogRotator:
    def __init__(
        self, max_size_bytes: int = 100 * 1024 * 1024, max_files: int = 10, max_age_days: int = 30
    ) -> None:
        self._max_size = max_size_bytes
        self._max_files = max_files
        self._max_age = max_age_days * 86400

    def should_rotate(self, path: Path) -> bool:
        if not path.exists():
            return False
        return path.stat().st_size >= self._max_size

    def rotate(self, path: Path) -> None:
        if not path.exists():
            return
        for i in range(self._max_files - 1, 0, -1):
            src = path.parent / f"{path.stem}.{i}{path.suffix}"
            dst = path.parent / f"{path.stem}.{i + 1}{path.suffix}"
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
        first_rotated = path.parent / f"{path.stem}.1{path.suffix}"
        if first_rotated.exists():
            first_rotated.unlink()
        path.rename(first_rotated)

    def cleanup_old(self, directory: Path, pattern: str = "*.jsonl*") -> int:
        removed = 0
        now = time.time()
        for f in directory.glob(pattern):
            if now - f.stat().st_mtime > self._max_age:
                f.unlink()
                removed += 1
        return removed
