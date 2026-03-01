"""Tests for config migration."""
import pytest
from butterfence.migration import migrate_config

class TestMigration:
    def test_v1_to_v2(self):
        v1_config = {
            "version": 1,
            "categories": {
                "destructive_shell": {
                    "enabled": True,
                    "severity": "critical",
                    "action": "block",
                    "patterns": ["rm -rf"],
                    "safe_list": [],
                },
            },
        }
        result = migrate_config(v1_config)
        assert result["version"] == 2
        assert "python_dangerous" in result["categories"]
        assert "sql_injection" in result["categories"]
        assert "docker_escape" in result["categories"]
        assert "cloud_credentials" in result["categories"]
        assert "supply_chain" in result["categories"]
        assert "privilege_escalation" in result["categories"]

    def test_preserves_existing_categories(self):
        v1_config = {
            "version": 1,
            "categories": {
                "destructive_shell": {
                    "enabled": True,
                    "severity": "critical",
                    "action": "block",
                    "patterns": ["rm -rf"],
                    "safe_list": [],
                },
            },
        }
        result = migrate_config(v1_config)
        assert result["categories"]["destructive_shell"]["patterns"] == ["rm -rf"]

    def test_adds_new_config_keys(self):
        v1_config = {"version": 1, "categories": {}}
        result = migrate_config(v1_config)
        assert "entropy_threshold" in result
        assert "behavioral_chains" in result
        assert "installed_packs" in result

    def test_already_v2(self):
        v2_config = {
            "version": 2,
            "categories": {"test": {"enabled": True, "severity": "high", "action": "block", "patterns": [], "safe_list": []}},
            "entropy_threshold": 4.5,
            "behavioral_chains": [],
            "installed_packs": [],
        }
        result = migrate_config(v2_config)
        assert result["version"] == 2

    def test_no_version_key(self):
        config = {"categories": {}}
        result = migrate_config(config)
        assert result["version"] == 2
