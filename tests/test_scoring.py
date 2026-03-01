"""Score calculation tests."""

import pytest

from butterfence.config import DEFAULT_CONFIG
from butterfence.scoring import ScoreResult, calculate_score


class TestCalculateScore:
    def test_perfect_score(self) -> None:
        results = [
            {"id": "s1", "name": "test", "category": "destructive_shell", "severity": "critical", "passed": True},
            {"id": "s2", "name": "test", "category": "secret_access", "severity": "critical", "passed": True},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert score.total_score == 100
        assert score.grade == "A"
        assert score.grade_label == "Hardened"
        assert len(score.deductions) == 0

    def test_critical_failure_deduction(self) -> None:
        results = [
            {"id": "s1", "name": "test", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert score.total_score == 85  # 100 - 15
        assert score.grade == "B"

    def test_high_failure_deduction(self) -> None:
        results = [
            {"id": "s1", "name": "test", "category": "risky_git", "severity": "high", "passed": False, "reason": "fail"},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert score.total_score == 90  # 100 - 10

    def test_multiple_failures(self) -> None:
        results = [
            {"id": "s1", "name": "t1", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"},
            {"id": "s2", "name": "t2", "category": "secret_access", "severity": "critical", "passed": False, "reason": "fail"},
            {"id": "s3", "name": "t3", "category": "risky_git", "severity": "high", "passed": False, "reason": "fail"},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert score.total_score == 60  # 100 - 15 - 15 - 10

    def test_score_minimum_zero(self) -> None:
        results = [
            {"id": f"s{i}", "name": "test", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"}
            for i in range(10)
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert score.total_score == 0
        assert score.grade == "F"

    def test_category_coverage(self) -> None:
        results = [
            {"id": "s1", "name": "t1", "category": "destructive_shell", "severity": "critical", "passed": True},
            {"id": "s2", "name": "t2", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert "destructive_shell" in score.category_coverage
        assert score.category_coverage["destructive_shell"]["total"] == 2
        assert score.category_coverage["destructive_shell"]["passed"] == 1
        assert score.category_coverage["destructive_shell"]["failed"] == 1

    def test_recommendations_generated(self) -> None:
        results = [
            {"id": "s1", "name": "t1", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"},
        ]
        score = calculate_score(results, DEFAULT_CONFIG)
        assert len(score.recommendations) > 0
