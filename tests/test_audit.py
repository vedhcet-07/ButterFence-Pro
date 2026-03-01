"""Audit scenario execution tests."""

import pytest

from butterfence.audit import load_scenarios, run_audit, run_scenario
from butterfence.config import DEFAULT_CONFIG


class TestLoadScenarios:
    def test_loads_all_scenarios(self) -> None:
        scenarios = load_scenarios()
        assert len(scenarios) == 44

    def test_scenario_structure(self) -> None:
        scenarios = load_scenarios()
        for s in scenarios:
            assert "id" in s
            assert "name" in s
            assert "category" in s
            assert "severity" in s
            assert "tool" in s
            assert "tool_input" in s
            assert "expected_decision" in s


class TestRunAudit:
    def test_all_scenarios_pass(self) -> None:
        """All 44 built-in scenarios should pass with default config."""
        results = run_audit(DEFAULT_CONFIG)
        assert len(results) == 44
        for r in results:
            assert r.passed, f"Scenario {r.id} ({r.name}) failed: expected {r.expected_decision}, got {r.actual_decision}"

    def test_quick_mode_filters_critical(self) -> None:
        results = run_audit(DEFAULT_CONFIG, quick=True)
        assert len(results) > 0
        assert all(r.severity == "critical" for r in results)

    def test_category_filter(self) -> None:
        results = run_audit(DEFAULT_CONFIG, category_filter="destructive_shell")
        assert len(results) > 0
        assert all(r.category == "destructive_shell" for r in results)

    def test_scenario_filter(self) -> None:
        results = run_audit(DEFAULT_CONFIG, scenario_filter="shell-001")
        assert len(results) == 1
        assert results[0].id == "shell-001"


class TestRunScenario:
    def test_single_scenario_block(self) -> None:
        scenario = {
            "id": "test-001",
            "name": "Test delete",
            "category": "destructive_shell",
            "severity": "critical",
            "tool": "Bash",
            "tool_input": {"command": "rm -rf / --no-preserve-root"},
            "expected_decision": "block",
        }
        result = run_scenario(scenario, DEFAULT_CONFIG)
        assert result.passed
        assert result.actual_decision == "block"

    def test_single_scenario_expected_allow(self) -> None:
        scenario = {
            "id": "test-002",
            "name": "Safe command",
            "category": "destructive_shell",
            "severity": "low",
            "tool": "Bash",
            "tool_input": {"command": "ls -la"},
            "expected_decision": "allow",
        }
        result = run_scenario(scenario, DEFAULT_CONFIG)
        assert result.passed
        assert result.actual_decision == "allow"
