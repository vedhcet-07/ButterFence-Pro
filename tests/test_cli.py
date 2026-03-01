"""Integration tests for CLI commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from butterfence.cli import app

runner = CliRunner()


class TestInit:
    def test_init_creates_config(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".butterfence" / "config.json").exists()

    def test_init_creates_directories(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".butterfence" / "logs").is_dir()
        assert (tmp_path / ".butterfence" / "reports").is_dir()

    def test_init_installs_hooks(self, tmp_path: Path) -> None:
        # Create .claude dir first
        (tmp_path / ".claude").mkdir()
        result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]

    def test_init_no_hooks(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "--no-hooks", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert not (tmp_path / ".claude" / "settings.local.json").exists()

    def test_init_idempotent(self, tmp_path: Path) -> None:
        (tmp_path / ".claude").mkdir()
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        # Should not duplicate hooks
        pre_hooks = settings["hooks"]["PreToolUse"]
        bf_hooks = [
            h for h in pre_hooks
            if any("butterfence" in hook.get("command", "") for hook in h.get("hooks", []))
        ]
        assert len(bf_hooks) == 3  # Bash, Read, Write|Edit

    def test_init_preserves_existing_hooks(self, tmp_path: Path) -> None:
        (tmp_path / ".claude").mkdir()
        existing = {
            "permissions": {"allow": ["WebSearch"]},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "CustomTool", "hooks": [{"type": "command", "command": "echo custom"}]}
                ]
            },
        }
        (tmp_path / ".claude" / "settings.local.json").write_text(json.dumps(existing))
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        # Custom hook should still be there
        custom_hooks = [
            h for h in settings["hooks"]["PreToolUse"]
            if h.get("matcher") == "CustomTool"
        ]
        assert len(custom_hooks) == 1
        # BF hooks also present
        assert "permissions" in settings


class TestAudit:
    def test_audit_runs(self, tmp_path: Path) -> None:
        # Need config
        runner.invoke(app, ["init", "--no-hooks", "--dir", str(tmp_path)])
        result = runner.invoke(app, ["audit", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "passed" in result.output

    def test_audit_quick(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", "--no-hooks", "--dir", str(tmp_path)])
        result = runner.invoke(app, ["audit", "--quick", "--dir", str(tmp_path)])
        assert result.exit_code == 0


class TestVersion:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Safety Harness" in result.output
