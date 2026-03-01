"""Educational threat explanations — `butterfence explain`."""

from __future__ import annotations

from pathlib import Path

import yaml

from butterfence.audit import SCENARIOS_PATH


def load_explanation(scenario_id: str, scenarios_path: Path | None = None) -> dict | None:
    """Load explanation for a specific scenario ID.

    Returns dict with keys: id, name, category, severity, explanation
    or None if not found.
    """
    path = scenarios_path or SCENARIOS_PATH
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for s in data.get("scenarios", []):
        if s.get("id") == scenario_id:
            return {
                "id": s["id"],
                "name": s.get("name", ""),
                "category": s.get("category", ""),
                "severity": s.get("severity", ""),
                "explanation": s.get("explanation", {}),
            }
    return None


def get_all_scenario_ids(scenarios_path: Path | None = None) -> list[str]:
    """Return all available scenario IDs."""
    path = scenarios_path or SCENARIOS_PATH
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return [s["id"] for s in data.get("scenarios", []) if "id" in s]
