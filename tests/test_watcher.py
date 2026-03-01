"""Tests for watcher/live dashboard."""
import json
import pytest
from pathlib import Path
from butterfence.watcher import EventTailer, WatchStats

class TestEventTailer:
    def test_poll_empty(self, tmp_path):
        log = tmp_path / "events.jsonl"
        log.touch()
        tailer = EventTailer(log)
        events = tailer.poll()
        assert events == []

    def test_poll_new_events(self, tmp_path):
        log = tmp_path / "events.jsonl"
        log.touch()
        tailer = EventTailer(log)

        # Write new event
        with open(log, "a") as f:
            f.write(json.dumps({"decision": "block", "tool_name": "Bash"}) + "\n")

        events = tailer.poll()
        assert len(events) == 1
        assert events[0]["decision"] == "block"

    def test_poll_multiple_events(self, tmp_path):
        log = tmp_path / "events.jsonl"
        log.touch()
        tailer = EventTailer(log)

        with open(log, "a") as f:
            for i in range(5):
                f.write(json.dumps({"decision": "allow", "index": i}) + "\n")

        events = tailer.poll()
        assert len(events) == 5

    def test_poll_incremental(self, tmp_path):
        log = tmp_path / "events.jsonl"
        log.touch()
        tailer = EventTailer(log)

        with open(log, "a") as f:
            f.write(json.dumps({"decision": "block"}) + "\n")
        events1 = tailer.poll()
        assert len(events1) == 1

        with open(log, "a") as f:
            f.write(json.dumps({"decision": "allow"}) + "\n")
        events2 = tailer.poll()
        assert len(events2) == 1
        assert events2[0]["decision"] == "allow"

    def test_nonexistent_file(self, tmp_path):
        tailer = EventTailer(tmp_path / "nonexistent.jsonl")
        events = tailer.poll()
        assert events == []

class TestWatchStats:
    def test_initial_state(self):
        stats = WatchStats()
        assert stats.blocks == 0
        assert stats.warns == 0
        assert stats.allows == 0
        assert stats.total == 0

    def test_total_count(self):
        stats = WatchStats()
        stats.blocks = 5
        stats.warns = 3
        stats.allows = 10
        assert stats.total == 18

    def test_events_per_min(self):
        stats = WatchStats()
        stats.blocks = 60
        # Can't reliably test time-based metric, just check it returns a float
        assert isinstance(stats.events_per_min, float)
