"""Tests for CVSS v3.1 scoring engine."""

import pytest

from butterfence.cvss import (
    AttackComplexity,
    AttackVector,
    CATEGORY_CVSS_VECTORS,
    CVSSResult,
    CVSSVector,
    ImpactMetric,
    PrivilegesRequired,
    Scope,
    UserInteraction,
    calculate_cvss_base_score,
    get_cvss_for_category,
)


class TestCVSSBaseScore:
    """Test CVSS v3.1 base score calculation against known reference values."""

    def test_zero_impact_yields_zero_score(self) -> None:
        """If all CIA impacts are None, score should be 0."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.NONE,
            integrity=ImpactMetric.NONE,
            availability=ImpactMetric.NONE,
        )
        result = calculate_cvss_base_score(vector)
        assert result.score == 0.0
        assert result.severity_label == "None"

    def test_high_impact_network_vector(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H should be 9.8."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH,
        )
        result = calculate_cvss_base_score(vector)
        assert result.score == 9.8
        assert result.severity_label == "Critical"

    def test_medium_severity_vector(self) -> None:
        """AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N should be medium-range."""
        vector = CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.LOW,
            integrity=ImpactMetric.LOW,
            availability=ImpactMetric.NONE,
        )
        result = calculate_cvss_base_score(vector)
        assert 3.0 <= result.score <= 6.9
        assert result.severity_label in ("Low", "Medium")

    def test_scope_changed_increases_score(self) -> None:
        """Changing scope should typically increase the score."""
        base_kwargs = dict(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.NONE,
            availability=ImpactMetric.NONE,
        )
        unchanged = calculate_cvss_base_score(
            CVSSVector(**base_kwargs, scope=Scope.UNCHANGED)
        )
        changed = calculate_cvss_base_score(
            CVSSVector(**base_kwargs, scope=Scope.CHANGED)
        )
        assert changed.score >= unchanged.score

    def test_vector_string_format(self) -> None:
        """Vector string should start with CVSS:3.1 and contain all metrics."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH,
        )
        result = calculate_cvss_base_score(vector)
        assert result.vector_string.startswith("CVSS:3.1/")
        assert "AV:" in result.vector_string
        assert "AC:" in result.vector_string
        assert "PR:" in result.vector_string
        assert "UI:" in result.vector_string
        assert "S:" in result.vector_string
        assert "C:" in result.vector_string
        assert "I:" in result.vector_string
        assert "A:" in result.vector_string

    def test_score_capped_at_10(self) -> None:
        """Score should never exceed 10.0."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=ImpactMetric.HIGH,
            integrity=ImpactMetric.HIGH,
            availability=ImpactMetric.HIGH,
        )
        result = calculate_cvss_base_score(vector)
        assert result.score <= 10.0

    def test_score_non_negative(self) -> None:
        """Score should never be negative."""
        vector = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=ImpactMetric.NONE,
            integrity=ImpactMetric.NONE,
            availability=ImpactMetric.NONE,
        )
        result = calculate_cvss_base_score(vector)
        assert result.score >= 0.0


class TestCategoryMapping:
    """Test that all 11 ButterFence categories have valid CVSS mappings."""

    EXPECTED_CATEGORIES = [
        "destructive_shell",
        "secret_access",
        "secret_exfil",
        "risky_git",
        "network_exfil",
        "python_dangerous",
        "sql_injection",
        "docker_escape",
        "cloud_credentials",
        "supply_chain",
        "privilege_escalation",
    ]

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_category_has_mapping(self, category: str) -> None:
        """Every ButterFence category should have a CVSS vector mapping."""
        assert category in CATEGORY_CVSS_VECTORS

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_category_produces_valid_score(self, category: str) -> None:
        """get_cvss_for_category should return valid CVSSResult."""
        result = get_cvss_for_category(category)
        assert isinstance(result, CVSSResult)
        assert 0.0 <= result.score <= 10.0
        assert result.severity_label in ("None", "Low", "Medium", "High", "Critical")
        assert result.vector_string.startswith("CVSS:3.1/")

    def test_unknown_category_gets_default(self) -> None:
        """An unknown category should get a medium-ish default score, not crash."""
        result = get_cvss_for_category("unknown_category_xyz")
        assert isinstance(result, CVSSResult)
        assert result.score > 0

    def test_docker_escape_is_critical(self) -> None:
        """Docker escape should be rated Critical (score >= 9.0)."""
        result = get_cvss_for_category("docker_escape")
        assert result.score >= 9.0
        assert result.severity_label == "Critical"

    def test_privilege_escalation_is_high_or_critical(self) -> None:
        """Privilege escalation should be at least High."""
        result = get_cvss_for_category("privilege_escalation")
        assert result.score >= 7.0
        assert result.severity_label in ("High", "Critical")


class TestCvssScoring:
    """Test CVSS-enhanced scoring in the scoring module."""

    def test_calculate_cvss_score_all_pass(self) -> None:
        from butterfence.config import DEFAULT_CONFIG
        from butterfence.scoring import calculate_cvss_score

        results = [
            {"id": "s1", "name": "test", "category": "destructive_shell", "severity": "critical", "passed": True},
        ]
        score = calculate_cvss_score(results, DEFAULT_CONFIG)
        assert score.total_score == 100
        assert score.max_cvss == 0.0
        assert score.avg_cvss == 0.0
        assert len(score.cvss_details) == 0

    def test_calculate_cvss_score_with_failures(self) -> None:
        from butterfence.config import DEFAULT_CONFIG
        from butterfence.scoring import calculate_cvss_score

        results = [
            {"id": "s1", "name": "t1", "category": "destructive_shell", "severity": "critical", "passed": False, "reason": "fail"},
            {"id": "s2", "name": "t2", "category": "secret_access", "severity": "critical", "passed": False, "reason": "fail"},
        ]
        score = calculate_cvss_score(results, DEFAULT_CONFIG)
        assert score.total_score < 100
        assert len(score.cvss_details) == 2
        assert score.max_cvss > 0
        assert score.avg_cvss > 0
        # Each detail should have required fields
        for d in score.cvss_details:
            assert "cvss_score" in d
            assert "cvss_severity" in d
            assert "cvss_vector" in d
