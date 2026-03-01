"""Tests for the natural language policy evaluation module."""

from __future__ import annotations

import json

import pytest

from butterfence.policy import (
    PolicyEvalResult,
    PolicyResult,
    PolicyViolation,
    _find_matching_policy,
    _parse_policy_response,
    evaluate_policies,
)


class TestPolicyDataclasses:
    """Verify dataclass fields and defaults."""

    def test_policy_result_dataclass(self) -> None:
        """PolicyResult fields."""
        pr = PolicyResult(
            policy="No file deletion allowed",
            violations=[{"id": "s-001", "name": "Delete root"}],
            compliant=[{"id": "s-002", "name": "Read config"}],
            reasoning="Deletion violates this policy",
        )
        assert pr.policy == "No file deletion allowed"
        assert len(pr.violations) == 1
        assert len(pr.compliant) == 1
        assert pr.reasoning == "Deletion violates this policy"

    def test_policy_result_defaults(self) -> None:
        """Default violations/compliant should be empty lists."""
        pr = PolicyResult(policy="test")
        assert pr.violations == []
        assert pr.compliant == []
        assert pr.reasoning == ""

    def test_policy_eval_result_dataclass(self) -> None:
        """PolicyEvalResult fields."""
        per = PolicyEvalResult(
            policies_checked=2,
            total_violations=3,
            results=[PolicyResult(policy="p1"), PolicyResult(policy="p2")],
            model_used="test-model",
        )
        assert per.policies_checked == 2
        assert per.total_violations == 3
        assert len(per.results) == 2
        assert per.model_used == "test-model"

    def test_policy_violation_dataclass(self) -> None:
        """PolicyViolation fields."""
        pv = PolicyViolation(
            scenario_id="shell-001",
            scenario_name="Delete root",
            reasoning="rm is deletion",
        )
        assert pv.scenario_id == "shell-001"
        assert pv.scenario_name == "Delete root"
        assert pv.reasoning == "rm is deletion"


class TestEvaluatePoliciesEdgeCases:
    """Tests for evaluate_policies without API calls."""

    def test_empty_policies_returns_empty(self) -> None:
        """Empty policies list returns 0 violations."""
        result = evaluate_policies([], [{"id": "s-001", "name": "test"}])
        assert result.policies_checked == 0
        assert result.total_violations == 0
        assert result.results == []

    def test_empty_scenarios_returns_compliant(self) -> None:
        """Policies with no scenarios return compliant results."""
        policies = ["Never delete files", "No network access"]
        result = evaluate_policies(policies, [])
        assert result.policies_checked == 2
        assert result.total_violations == 0
        assert len(result.results) == 2
        for pr in result.results:
            assert pr.violations == []
            assert pr.compliant == []


_POLICIES = ["Never delete files", "No installing unknown packages"]
_SCENARIOS = [
    {
        "id": "shell-001",
        "name": "Delete root",
        "category": "destructive_shell",
        "severity": "critical",
        "tool": "Bash",
    },
    {
        "id": "supply-001",
        "name": "Pip install from HTTP",
        "category": "supply_chain",
        "severity": "high",
        "tool": "Bash",
    },
]


class TestParsePolicyResponse:
    """Tests for _parse_policy_response."""

    def test_parse_policy_response_valid(self) -> None:
        """Valid JSON array should parse correctly."""
        raw = json.dumps([
            {
                "policy": "Never delete files",
                "violations": ["shell-001"],
                "reasoning": "rm is deletion",
            },
            {
                "policy": "No installing unknown packages",
                "violations": [],
                "reasoning": "No supply chain issues",
            },
        ])

        results = _parse_policy_response(raw, _POLICIES, _SCENARIOS)

        assert len(results) == 2
        r0 = results[0]
        assert r0.policy == "Never delete files"
        assert len(r0.violations) == 1
        assert r0.violations[0]["id"] == "shell-001"
        assert len(r0.compliant) == 1
        assert r0.compliant[0]["id"] == "supply-001"
        assert r0.reasoning == "rm is deletion"

        r1 = results[1]
        assert r1.policy == "No installing unknown packages"
        assert len(r1.violations) == 0
        assert len(r1.compliant) == 2

    def test_parse_policy_response_fenced(self) -> None:
        """Markdown-fenced JSON should be unwrapped."""
        inner = json.dumps([
            {
                "policy": "Never delete files",
                "violations": ["shell-001"],
                "reasoning": "Deletion detected",
            },
        ])
        bt = chr(96) * 3
        fenced = bt + "json" + chr(10) + inner + chr(10) + bt

        results = _parse_policy_response(fenced, _POLICIES, _SCENARIOS)

        assert len(results) >= 1
        matched = [r for r in results if r.policy == "Never delete files"]
        assert len(matched) == 1
        assert len(matched[0].violations) == 1

    def test_parse_policy_response_empty(self) -> None:
        """Empty response returns empty results for each policy."""
        results = _parse_policy_response("", _POLICIES, _SCENARIOS)

        assert len(results) == len(_POLICIES)
        for r in results:
            assert r.violations == []
            assert "Could not parse" in r.reasoning


class TestFindMatchingPolicy:
    """Tests for the fuzzy policy matching helper."""

    def test_exact_match(self) -> None:
        """Exact text match."""
        policies = ["Never delete files", "No network access"]
        result = _find_matching_policy("Never delete files", policies)
        assert result == "Never delete files"

    def test_case_insensitive_match(self) -> None:
        """Case-insensitive matching."""
        policies = ["Never delete files"]
        result = _find_matching_policy("NEVER DELETE FILES", policies)
        assert result == "Never delete files"

    def test_substring_match(self) -> None:
        """Substring containment."""
        policies = ["Never delete files in production"]
        result = _find_matching_policy("delete files", policies)
        assert result == "Never delete files in production"

    def test_no_match_returns_none(self) -> None:
        """Completely unrelated text."""
        policies = ["Never delete files"]
        result = _find_matching_policy("Launch rockets to mars", policies)
        assert result is None

    def test_whitespace_tolerance(self) -> None:
        """Leading/trailing whitespace."""
        policies = ["Never delete files"]
        result = _find_matching_policy("  Never delete files  ", policies)
        assert result == "Never delete files"
