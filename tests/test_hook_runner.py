"""stdin/stdout JSON contract tests for hook runner."""

import json
import pytest

from butterfence.hook_runner import _make_hook_output, _summarize_input
from butterfence.matcher import HookPayload, MatchResult, match_rules
from butterfence.config import DEFAULT_CONFIG


class TestMakeHookOutput:
    def test_block_output(self) -> None:
        result = MatchResult(decision="block", reason="test reason")
        output = _make_hook_output("PreToolUse", result)
        assert output is not None
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "[ButterFence]" in output["hookSpecificOutput"]["permissionDecisionReason"]

    def test_warn_output(self) -> None:
        result = MatchResult(decision="warn", reason="test warning")
        output = _make_hook_output("PreToolUse", result)
        assert output is not None
        assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "[ButterFence WARNING]" in output["hookSpecificOutput"]["permissionDecisionReason"]

    def test_allow_output(self) -> None:
        result = MatchResult(decision="allow")
        output = _make_hook_output("PreToolUse", result)
        assert output is None

    def test_block_json_serializable(self) -> None:
        result = MatchResult(decision="block", reason="dangerous command detected")
        output = _make_hook_output("PreToolUse", result)
        serialized = json.dumps(output)
        parsed = json.loads(serialized)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestSummarizeInput:
    def test_command_input(self) -> None:
        summary = _summarize_input({"command": "rm -rf /"})
        assert "rm -rf /" in summary

    def test_file_path_input(self) -> None:
        summary = _summarize_input({"file_path": "/etc/passwd"})
        assert "/etc/passwd" in summary

    def test_long_command_truncated(self) -> None:
        long_cmd = "x" * 500
        summary = _summarize_input({"command": long_cmd})
        assert len(summary) <= 200


class TestEndToEndContract:
    """Test the full hook input -> matcher -> output pipeline."""

    def test_dangerous_command_produces_deny(self) -> None:
        payload = HookPayload(
            hook_event="PreToolUse",
            tool_name="Bash",
            tool_input={"command": "rm -rf / --no-preserve-root"},
        )
        result = match_rules(payload, DEFAULT_CONFIG)
        output = _make_hook_output("PreToolUse", result)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_safe_command_produces_no_output(self) -> None:
        payload = HookPayload(
            hook_event="PreToolUse",
            tool_name="Bash",
            tool_input={"command": "ls -la"},
        )
        result = match_rules(payload, DEFAULT_CONFIG)
        output = _make_hook_output("PreToolUse", result)
        assert output is None
