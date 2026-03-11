"""Unit tests for log rotation."""

from __future__ import annotations

import os
import time

from skillsecurity.audit.rotation import LogRotator


class TestLogRotator:
    def test_should_rotate_large_file(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_bytes(b"x" * 200)
        rotator = LogRotator(max_size_bytes=100)
        assert rotator.should_rotate(f) is True

    def test_should_not_rotate_small_file(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_bytes(b"x" * 50)
        rotator = LogRotator(max_size_bytes=100)
        assert rotator.should_rotate(f) is False

    def test_should_not_rotate_nonexistent(self, tmp_path):
        f = tmp_path / "no.jsonl"
        rotator = LogRotator()
        assert rotator.should_rotate(f) is False

    def test_rotate_creates_numbered_file(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text("entry1")
        rotator = LogRotator()
        rotator.rotate(f)
        assert not f.exists()
        rotated = tmp_path / "log.1.jsonl"
        assert rotated.exists()
        assert rotated.read_text() == "entry1"

    def test_rotate_shifts_existing(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text("new")
        f1 = tmp_path / "log.1.jsonl"
        f1.write_text("old")
        rotator = LogRotator(max_files=5)
        rotator.rotate(f)
        assert not f.exists()
        assert (tmp_path / "log.1.jsonl").read_text() == "new"
        assert (tmp_path / "log.2.jsonl").read_text() == "old"

    def test_rotate_nonexistent_noop(self, tmp_path):
        f = tmp_path / "no.jsonl"
        rotator = LogRotator()
        rotator.rotate(f)

    def test_cleanup_old_files(self, tmp_path):
        old = tmp_path / "old.jsonl"
        old.write_text("old data")
        very_old = time.time() - (40 * 86400)
        os.utime(old, (very_old, very_old))
        rotator = LogRotator(max_age_days=30)
        removed = rotator.cleanup_old(tmp_path)
        assert removed == 1
        assert not old.exists()

    def test_cleanup_keeps_recent(self, tmp_path):
        recent = tmp_path / "recent.jsonl"
        recent.write_text("recent data")
        rotator = LogRotator(max_age_days=30)
        removed = rotator.cleanup_old(tmp_path)
        assert removed == 0
        assert recent.exists()
