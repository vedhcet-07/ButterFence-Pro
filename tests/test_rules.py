"""Pattern compilation tests."""

import re

import pytest

from butterfence.config import DEFAULT_CONFIG
from butterfence.rules import Action, Category, CompiledRule, Severity, compile_rules


class TestCompileRules:
    def test_compiles_all_categories(self) -> None:
        rules = compile_rules(DEFAULT_CONFIG)
        assert len(rules) > 0
        categories = {r.category for r in rules}
        assert "destructive_shell" in categories
        assert "secret_access" in categories
        assert "secret_exfil" in categories
        assert "risky_git" in categories
        assert "network_exfil" in categories

    def test_disabled_category_excluded(self) -> None:
        config = {
            "categories": {
                "test_cat": {
                    "enabled": False,
                    "severity": "high",
                    "action": "block",
                    "patterns": [r"dangerous"],
                    "safe_list": [],
                }
            }
        }
        rules = compile_rules(config)
        assert len(rules) == 0

    def test_invalid_regex_skipped(self) -> None:
        config = {
            "categories": {
                "test_cat": {
                    "enabled": True,
                    "severity": "high",
                    "action": "block",
                    "patterns": [r"valid", r"[invalid"],
                    "safe_list": [],
                }
            }
        }
        rules = compile_rules(config)
        assert len(rules) == 1
        assert rules[0].raw_pattern == "valid"

    def test_safe_patterns_compiled(self) -> None:
        rules = compile_rules(DEFAULT_CONFIG)
        shell_rules = [r for r in rules if r.category == "destructive_shell"]
        assert any(len(r.safe_patterns) > 0 for r in shell_rules)


class TestEnums:
    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_action_values(self) -> None:
        assert Action.BLOCK.value == "block"
        assert Action.WARN.value == "warn"
        assert Action.ALLOW.value == "allow"
