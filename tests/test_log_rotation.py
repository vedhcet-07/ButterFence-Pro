"""Tests for log rotation."""
import pytest
from pathlib import Path
from butterfence.log_rotation import rotate_if_needed

class TestLogRotation:
    def test_no_rotation_small_file(self, tmp_path):
        log = tmp_path / "events.jsonl"
        log.write_text("small content\n")
        assert rotate_if_needed(log, max_size_mb=10) is False

    def test_rotation_happens(self, tmp_path):
        log = tmp_path / "events.jsonl"
        # Write >1MB
        log.write_bytes(b"x" * (1024 * 1024 + 100))
        result = rotate_if_needed(log, max_size_mb=1)
        assert result is True
        assert (tmp_path / "events.jsonl.1").exists()
        assert log.exists()  # New empty log created

    def test_no_file(self, tmp_path):
        log = tmp_path / "nonexistent.jsonl"
        assert rotate_if_needed(log) is False

    def test_multiple_rotations(self, tmp_path):
        log = tmp_path / "events.jsonl"
        # First rotation
        log.write_bytes(b"x" * (2 * 1024 * 1024))
        rotate_if_needed(log, max_size_mb=1, keep=3)
        assert (tmp_path / "events.jsonl.1").exists()

        # Second rotation
        log.write_bytes(b"y" * (2 * 1024 * 1024))
        rotate_if_needed(log, max_size_mb=1, keep=3)
        assert (tmp_path / "events.jsonl.2").exists()

    def test_keep_limit(self, tmp_path):
        log = tmp_path / "events.jsonl"
        for i in range(5):
            log.write_bytes(b"x" * (2 * 1024 * 1024))
            rotate_if_needed(log, max_size_mb=1, keep=2)
        # Should only keep .1 and .2
        assert (tmp_path / "events.jsonl.1").exists()
        assert (tmp_path / "events.jsonl.2").exists()
        assert not (tmp_path / "events.jsonl.3").exists()
