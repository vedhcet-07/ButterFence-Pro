"""SARIF 2.1.0 output — GitHub Code Scanning compatible."""

from __future__ import annotations

from butterfence import __version__

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def audit_to_sarif(audit_results: list[dict], config: dict | None = None) -> dict:
    """Convert audit results to SARIF 2.1.0 format.

    Compatible with GitHub Code Scanning / Security tab.
    """
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for r in audit_results:
        rule_id = r.get("id", "unknown")
        category = r.get("category", "unknown")
        severity = r.get("severity", "high")
        passed = r.get("passed", False)

        # Define rule if not yet seen
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": r.get("name", rule_id),
                "shortDescription": {"text": r.get("name", rule_id)},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(severity, "warning"),
                },
                "properties": {
                    "category": category,
                    "severity": severity,
                },
            })

        if not passed:
            results.append({
                "ruleId": rule_id,
                "level": _SEVERITY_TO_SARIF.get(severity, "warning"),
                "message": {
                    "text": f"Scenario '{r.get('name', rule_id)}' failed: "
                    f"expected {r.get('expected_decision', 'block')}, "
                    f"got {r.get('actual_decision', 'allow')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": ".butterfence/config.json",
                            },
                        }
                    }
                ],
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ButterFence",
                        "version": __version__,
                        "informationUri": "https://github.com/anthropics/butterfence",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
