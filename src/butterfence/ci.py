"""CI/CD integration — `butterfence ci`."""

from __future__ import annotations

import json
from pathlib import Path

from butterfence.audit import run_audit
from butterfence.config import load_config
from butterfence.scoring import calculate_score


def run_ci(
    project_dir: Path,
    min_score: int = 80,
    output_format: str = "json",
    output_file: Path | None = None,
    badge_file: Path | None = None,
) -> tuple[bool, dict]:
    """Run CI audit, return (passed, results_dict).

    Returns True if score >= min_score.
    """
    config = load_config(project_dir)
    results = run_audit(config=config)

    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in results
    ]

    score = calculate_score(audit_dicts, config)
    passed = score.total_score >= min_score

    # Generate output in requested format
    output = _format_output(output_format, score, audit_dicts)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output, encoding="utf-8")

    # Generate badge if requested
    if badge_file:
        from butterfence.exporters.badge import generate_badge

        badge_svg = generate_badge(score.total_score, score.grade)
        badge_file.parent.mkdir(parents=True, exist_ok=True)
        badge_file.write_text(badge_svg, encoding="utf-8")

    return passed, {
        "score": score.total_score,
        "max_score": score.max_score,
        "grade": score.grade,
        "passed": passed,
        "min_score": min_score,
        "scenarios_passed": sum(1 for r in audit_dicts if r["passed"]),
        "scenarios_failed": sum(1 for r in audit_dicts if not r["passed"]),
        "scenarios_total": len(audit_dicts),
    }


def _format_output(
    fmt: str,
    score,
    audit_dicts: list[dict],
) -> str:
    if fmt == "sarif":
        from butterfence.exporters.sarif import audit_to_sarif

        return json.dumps(audit_to_sarif(audit_dicts), indent=2)
    elif fmt == "junit":
        from butterfence.exporters.junit import audit_to_junit

        return audit_to_junit(audit_dicts)
    else:  # json
        from butterfence.exporters.json_export import audit_to_json

        return json.dumps(audit_to_json(score, audit_dicts), indent=2)


def generate_github_workflow() -> str:
    """Generate a GitHub Actions workflow YAML for ButterFence."""
    return """name: ButterFence Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  butterfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install ButterFence
        run: pip install butterfence

      - name: Initialize ButterFence
        run: butterfence init --no-hooks

      - name: Run Security Audit
        run: butterfence ci --min-score 80 --format sarif --output results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
"""
