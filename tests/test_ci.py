"""Tests for CI integration."""
import json
import pytest
from pathlib import Path
from butterfence.ci import run_ci, generate_github_workflow
from butterfence.config import DEFAULT_CONFIG, save_config

class TestRunCI:
    def _setup_project(self, tmp_path):
        """Set up a minimal ButterFence project."""
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        (bf_dir / "logs").mkdir()
        (bf_dir / "reports").mkdir()
        save_config(DEFAULT_CONFIG, tmp_path)
        return tmp_path

    def test_ci_passes_default_config(self, tmp_path):
        project = self._setup_project(tmp_path)
        passed, info = run_ci(project, min_score=80)
        assert passed is True
        assert info["score"] >= 80

    def test_ci_returns_info(self, tmp_path):
        project = self._setup_project(tmp_path)
        _, info = run_ci(project)
        assert "score" in info
        assert "grade" in info
        assert "passed" in info
        assert "scenarios_total" in info
        assert "scenarios_passed" in info

    def test_ci_high_min_score(self, tmp_path):
        project = self._setup_project(tmp_path)
        passed, info = run_ci(project, min_score=100)
        assert info["score"] <= 100

    def test_ci_json_output(self, tmp_path):
        project = self._setup_project(tmp_path)
        output_file = tmp_path / "results.json"
        run_ci(project, output_format="json", output_file=output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "score" in data
        assert "scenarios" in data

    def test_ci_sarif_output(self, tmp_path):
        project = self._setup_project(tmp_path)
        output_file = tmp_path / "results.sarif"
        run_ci(project, output_format="sarif", output_file=output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["version"] == "2.1.0"

    def test_ci_junit_output(self, tmp_path):
        project = self._setup_project(tmp_path)
        output_file = tmp_path / "results.xml"
        run_ci(project, output_format="junit", output_file=output_file)
        assert output_file.exists()
        content = output_file.read_text()
        assert "testsuite" in content

    def test_ci_badge_output(self, tmp_path):
        project = self._setup_project(tmp_path)
        badge_file = tmp_path / "badge.svg"
        run_ci(project, badge_file=badge_file)
        assert badge_file.exists()
        content = badge_file.read_text()
        assert "<svg" in content

    def test_ci_zero_min_score(self, tmp_path):
        project = self._setup_project(tmp_path)
        passed, _ = run_ci(project, min_score=0)
        assert passed is True

class TestGenerateWorkflow:
    def test_workflow_content(self):
        content = generate_github_workflow()
        assert "butterfence" in content
        assert "pip install" in content
        assert "sarif" in content

    def test_workflow_is_valid_yaml(self):
        import yaml
        content = generate_github_workflow()
        data = yaml.safe_load(content)
        assert "jobs" in data
