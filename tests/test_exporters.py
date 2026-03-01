"""Tests for export format modules."""
import json
import pytest
from butterfence.exporters.sarif import audit_to_sarif
from butterfence.exporters.junit import audit_to_junit
from butterfence.exporters.json_export import audit_to_json
from butterfence.exporters.html_report import generate_html_report
from butterfence.exporters.badge import generate_badge
from butterfence.scoring import ScoreResult

SAMPLE_RESULTS = [
    {"id": "test-001", "name": "Test pass", "category": "test", "severity": "high",
     "passed": True, "expected_decision": "block", "actual_decision": "block", "reason": ""},
    {"id": "test-002", "name": "Test fail", "category": "test", "severity": "critical",
     "passed": False, "expected_decision": "block", "actual_decision": "allow", "reason": "Failed"},
]

SAMPLE_SCORE = ScoreResult(
    total_score=85, max_score=100, grade="B", grade_label="Mostly Safe",
    deductions=[{"scenario": "test-002", "name": "Test fail", "category": "test",
                 "severity": "critical", "points": -15, "reason": ""}],
    category_coverage={"test": {"total": 2, "passed": 1, "failed": 1}},
    recommendations=["Fix test category"],
)

class TestSARIF:
    def test_valid_sarif_structure(self):
        result = audit_to_sarif(SAMPLE_RESULTS)
        assert result["version"] == "2.1.0"
        assert len(result["runs"]) == 1

    def test_sarif_has_rules(self):
        result = audit_to_sarif(SAMPLE_RESULTS)
        rules = result["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_sarif_has_results_for_failures(self):
        result = audit_to_sarif(SAMPLE_RESULTS)
        results = result["runs"][0]["results"]
        assert len(results) == 1  # Only failures

    def test_sarif_all_pass(self):
        result = audit_to_sarif([SAMPLE_RESULTS[0]])  # Only passed
        results = result["runs"][0]["results"]
        assert len(results) == 0

class TestJUnit:
    def test_valid_xml(self):
        xml = audit_to_junit(SAMPLE_RESULTS)
        assert "<?xml" in xml
        assert "testsuite" in xml

    def test_test_count(self):
        xml = audit_to_junit(SAMPLE_RESULTS)
        assert 'tests="2"' in xml

    def test_failure_count(self):
        xml = audit_to_junit(SAMPLE_RESULTS)
        assert 'failures="1"' in xml

class TestJSON:
    def test_has_required_keys(self):
        result = audit_to_json(SAMPLE_SCORE, SAMPLE_RESULTS)
        assert "score" in result
        assert "summary" in result
        assert "scenarios" in result
        assert "recommendations" in result

    def test_score_values(self):
        result = audit_to_json(SAMPLE_SCORE, SAMPLE_RESULTS)
        assert result["score"]["total"] == 85
        assert result["score"]["grade"] == "B"

class TestHTML:
    def test_generates_html(self):
        html = generate_html_report(SAMPLE_SCORE, SAMPLE_RESULTS)
        assert "<!DOCTYPE html>" in html
        assert "ButterFence" in html

    def test_contains_score(self):
        html = generate_html_report(SAMPLE_SCORE, SAMPLE_RESULTS)
        assert "85" in html
        assert "Mostly Safe" in html

    def test_self_contained(self):
        html = generate_html_report(SAMPLE_SCORE, SAMPLE_RESULTS)
        assert "<style>" in html
        # No external CSS/JS references
        assert "stylesheet" not in html.lower() or "href=" not in html

class TestBadge:
    def test_generates_svg(self):
        svg = generate_badge(95, "A")
        assert "<svg" in svg
        assert "ButterFence" in svg

    def test_score_in_badge(self):
        svg = generate_badge(85, "B")
        assert "85/100" in svg
        assert "(B)" in svg

    def test_grade_colors(self):
        svg_a = generate_badge(95, "A")
        svg_f = generate_badge(30, "F")
        # A should have green color #4c1, F should have red #e05d44
        assert "#4c1" in svg_a
        assert "#e05d44" in svg_f
