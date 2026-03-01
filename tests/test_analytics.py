"""Tests for analytics module."""
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from butterfence.analytics import analyze_events, AnalyticsResult

def _write_events(log_path, events):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

class TestAnalytics:
    def test_no_events(self, tmp_path):
        result = analyze_events(tmp_path)
        assert result.total_events == 0
        assert result.blocks == 0

    def test_counts_decisions(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        events = [
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "block", "tool_name": "Bash", "reason": "[high:destructive_shell] matched"},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "block", "tool_name": "Bash", "reason": "[high:secret_access] matched"},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "warn", "tool_name": "Read", "reason": ""},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Write", "reason": ""},
        ]
        _write_events(log, events)
        result = analyze_events(tmp_path)
        assert result.total_events == 5
        assert result.blocks == 2
        assert result.warns == 1
        assert result.allows == 2

    def test_by_tool(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        events = [
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Read", "reason": ""},
        ]
        _write_events(log, events)
        result = analyze_events(tmp_path)
        assert result.by_tool["Bash"] == 2
        assert result.by_tool["Read"] == 1

    def test_block_rate(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        events = [
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "block", "tool_name": "Bash", "reason": ""},
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""},
        ]
        _write_events(log, events)
        result = analyze_events(tmp_path)
        assert abs(result.block_rate - 50.0) < 0.1

    def test_period_filter(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        now = datetime.now(timezone.utc)
        events = [
            {"timestamp": now.isoformat(), "decision": "block", "tool_name": "Bash", "reason": ""},
        ]
        _write_events(log, events)
        result = analyze_events(tmp_path, period="1h")
        assert result.total_events == 1

    def test_missing_log(self, tmp_path):
        result = analyze_events(tmp_path)
        assert result.total_events == 0

    def test_malformed_json_skipped(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "w") as f:
            f.write("not json\n")
            f.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""}) + "\n")
        result = analyze_events(tmp_path)
        assert result.total_events == 1

    def test_threat_trend_default(self, tmp_path):
        log = tmp_path / ".butterfence" / "logs" / "events.jsonl"
        events = [
            {"timestamp": datetime.now(timezone.utc).isoformat(), "decision": "allow", "tool_name": "Bash", "reason": ""},
        ]
        _write_events(log, events)
        result = analyze_events(tmp_path)
        assert result.threat_trend == "stable"
