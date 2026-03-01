"""JSON export for audit results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from butterfence import __version__
from butterfence.scoring import ScoreResult


def audit_to_json(score_result: ScoreResult, audit_results: list[dict]) -> dict:
    """Convert score and audit results to a structured JSON dict."""
    return {
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": {
            "total": score_result.total_score,
            "max": score_result.max_score,
            "grade": score_result.grade,
            "grade_label": score_result.grade_label,
        },
        "summary": {
            "total_scenarios": len(audit_results),
            "passed": sum(1 for r in audit_results if r.get("passed", False)),
            "failed": sum(1 for r in audit_results if not r.get("passed", False)),
        },
        "scenarios": audit_results,
        "deductions": score_result.deductions,
        "category_coverage": score_result.category_coverage,
        "recommendations": score_result.recommendations,
    }


def audit_to_json_string(score_result: ScoreResult, audit_results: list[dict]) -> str:
    """Return formatted JSON string."""
    return json.dumps(audit_to_json(score_result, audit_results), indent=2)
