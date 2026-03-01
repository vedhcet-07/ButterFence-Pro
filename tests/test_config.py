"""Config loading/validation tests."""

import json
import pytest
from pathlib import Path

from butterfence.config import DEFAULT_CONFIG, load_config, save_config, validate_config
from butterfence.utils import deep_merge


class TestDefaultConfig:
    def test_has_all_categories(self) -> None:
        cats = DEFAULT_CONFIG["categories"]
        assert "destructive_shell" in cats
        assert "secret_access" in cats
        assert "secret_exfil" in cats
        assert "risky_git" in cats
        assert "network_exfil" in cats

    def test_all_categories_have_patterns(self) -> None:
        for name, cat in DEFAULT_CONFIG["categories"].items():
            assert len(cat["patterns"]) > 0, f"{name} has no patterns"

    def test_validates_clean(self) -> None:
        errors = validate_config(DEFAULT_CONFIG)
        assert errors == []


class TestValidation:
    def test_missing_categories(self) -> None:
        errors = validate_config({})
        assert len(errors) > 0

    def test_invalid_severity(self) -> None:
        config = {
            "categories": {
                "test": {
                    "enabled": True,
                    "severity": "extreme",
                    "action": "block",
                    "patterns": [],
                }
            }
        }
        errors = validate_config(config)
        assert any("severity" in e for e in errors)

    def test_invalid_action(self) -> None:
        config = {
            "categories": {
                "test": {
                    "enabled": True,
                    "severity": "high",
                    "action": "nuke",
                    "patterns": [],
                }
            }
        }
        errors = validate_config(config)
        assert any("action" in e for e in errors)


class TestDeepMerge:
    def test_simple_merge(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self) -> None:
        base = {"a": {"x": 1, "y": 2}}
        override = {"a": {"y": 3, "z": 4}}
        result = deep_merge(base, override)
        assert result == {"a": {"x": 1, "y": 3, "z": 4}}

    def test_base_unchanged(self) -> None:
        base = {"a": 1}
        override = {"a": 2}
        deep_merge(base, override)
        assert base == {"a": 1}


class TestSaveLoadConfig:
    def test_save_and_load(self, tmp_path: Path) -> None:
        save_config(DEFAULT_CONFIG, tmp_path)
        config_file = tmp_path / ".butterfence" / "config.json"
        assert config_file.exists()

        loaded = load_config(tmp_path)
        assert loaded["categories"]["destructive_shell"]["enabled"] is True
