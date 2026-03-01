"""Audit orchestrator: load scenarios, run matcher, collect results."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from butterfence.matcher import HookPayload, MatchResult, match_rules

logger = logging.getLogger(__name__)

SCENARIOS_PATH = Path(__file__).parent.parent.parent / "assets" / "scenarios.yaml"


@dataclass
class ScenarioResult:
    id: str
    name: str
    category: str
    severity: str
    expected_decision: str
    actual_decision: str
    passed: bool
    match_result: MatchResult
    reason: str = ""


def load_scenarios(path: Path | None = None) -> list[dict]:
    """Load red-team scenarios from YAML file."""
    scenarios_file = path or SCENARIOS_PATH
    # Also check package-relative path
    if not scenarios_file.exists():
        alt = Path(__file__).parent.parent.parent / "assets" / "scenarios.yaml"
        if alt.exists():
            scenarios_file = alt
        else:
            logger.warning("Scenarios file not found: %s", scenarios_file)
            return []  # Return empty list instead of crashing

    try:
        with open(scenarios_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse scenarios YAML: %s", exc)
        return []

    return data.get("scenarios", []) if isinstance(data, dict) else []


def run_scenario(scenario: dict, config: dict) -> ScenarioResult:
    """Run a single audit scenario through the matcher."""
    required = ("id", "name", "category", "severity")
    for key in required:
        if key not in scenario:
            raise ValueError(f"Scenario missing required field: {key}")

    payload = HookPayload(
        hook_event="PreToolUse",
        tool_name=scenario.get("tool", "Bash"),
        tool_input=scenario.get("tool_input", {}),
    )

    result = match_rules(payload, config)
    expected = scenario.get("expected_decision", "block")
    passed = result.decision == expected

    return ScenarioResult(
        id=scenario["id"],
        name=scenario["name"],
        category=scenario["category"],
        severity=scenario["severity"],
        expected_decision=expected,
        actual_decision=result.decision,
        passed=passed,
        match_result=result,
        reason="" if passed else f"Expected {expected}, got {result.decision}",
    )


def run_audit(
    config: dict,
    scenarios_path: Path | None = None,
    category_filter: str | None = None,
    scenario_filter: str | None = None,
    quick: bool = False,
) -> list[ScenarioResult]:
    """Run all audit scenarios and return results."""
    scenarios = load_scenarios(scenarios_path)

    if category_filter:
        scenarios = [s for s in scenarios if s["category"] == category_filter]

    if scenario_filter:
        scenarios = [s for s in scenarios if s["id"] == scenario_filter]

    if quick:
        scenarios = [s for s in scenarios if s.get("severity") == "critical"]

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        try:
            result = run_scenario(scenario, config)
            results.append(result)
        except Exception as exc:
            logger.warning("Scenario %s failed: %s", scenario.get("id", "unknown"), exc)
            results.append(ScenarioResult(
                id=scenario.get("id", "unknown"),
                name=scenario.get("name", "unknown"),
                category=scenario.get("category", "unknown"),
                severity=scenario.get("severity", "high"),
                expected_decision=scenario.get("expected_decision", "block"),
                actual_decision="error",
                passed=False,
                match_result=MatchResult(decision="error", reason=str(exc)),
                reason=f"Scenario error: {exc}",
            ))

    return results
