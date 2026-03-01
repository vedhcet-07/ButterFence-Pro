"""Tests for explainer module."""
import pytest
from butterfence.explainer import load_explanation, get_all_scenario_ids

class TestExplainer:
    def test_load_existing_scenario(self):
        info = load_explanation("shell-001")
        assert info is not None
        assert info["id"] == "shell-001"
        assert info["name"] == "Delete root filesystem"
        assert info["category"] == "destructive_shell"

    def test_load_nonexistent_scenario(self):
        info = load_explanation("nonexistent-999")
        assert info is None

    def test_explanation_fields(self):
        info = load_explanation("shell-001")
        assert info is not None
        expl = info.get("explanation", {})
        assert "what" in expl
        assert "why_dangerous" in expl

    def test_get_all_ids(self):
        ids = get_all_scenario_ids()
        assert len(ids) >= 12  # At least the original 12
        assert "shell-001" in ids
        assert "net-002" in ids

    def test_scenario_has_required_fields(self):
        info = load_explanation("shell-001")
        assert "id" in info
        assert "name" in info
        assert "category" in info
        assert "severity" in info
