"""Hook installation into .claude/settings.local.json."""

from __future__ import annotations

import sys
from pathlib import Path

from butterfence.utils import deep_merge, load_json, save_json

BUTTERFENCE_MARKER = "butterfence.hook_runner"


def _get_python_path() -> str:
    """Get the current Python executable path, quoted for shell use."""
    return sys.executable.replace("\\", "/")


def _make_hook_entry(matcher: str, mode: str, python_path: str, timeout: int = 10) -> dict:
    """Create a single hook config entry."""
    return {
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": f'"{python_path}" -m butterfence.hook_runner {mode}',
                "timeout": timeout,
            }
        ],
    }


def generate_hook_config() -> dict:
    """Generate the full hooks configuration for ButterFence."""
    python_path = _get_python_path()
    return {
        "hooks": {
            "PreToolUse": [
                _make_hook_entry("Bash", "pretool", python_path),
                _make_hook_entry("Read", "pretool", python_path),
                _make_hook_entry("Write|Edit", "pretool", python_path),
            ],
            "PostToolUse": [
                _make_hook_entry("Bash|Read|Write|Edit", "posttool", python_path),
            ],
        }
    }


def _remove_butterfence_hooks(hooks_list: list[dict]) -> list[dict]:
    """Remove any existing ButterFence hooks from a hooks list."""
    return [
        h for h in hooks_list
        if not any(
            BUTTERFENCE_MARKER in hook.get("command", "")
            for hook in h.get("hooks", [])
        )
    ]


def install_hooks(project_dir: Path) -> Path:
    """Install ButterFence hooks into .claude/settings.local.json.

    Merges with existing settings, removing old BF hooks first.
    Returns path to the settings file.
    """
    settings_path = project_dir / ".claude" / "settings.local.json"
    existing = load_json(settings_path)

    # Remove old ButterFence hooks from existing config
    if "hooks" in existing:
        for event_name in ("PreToolUse", "PostToolUse"):
            if event_name in existing["hooks"]:
                existing["hooks"][event_name] = _remove_butterfence_hooks(
                    existing["hooks"][event_name]
                )

    # Generate new BF hooks
    bf_config = generate_hook_config()

    # Merge: append BF hooks to existing hooks
    if "hooks" not in existing:
        existing["hooks"] = {}

    for event_name in ("PreToolUse", "PostToolUse"):
        existing_hooks = existing["hooks"].get(event_name, [])
        bf_hooks = bf_config["hooks"].get(event_name, [])
        existing["hooks"][event_name] = existing_hooks + bf_hooks

    try:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        save_json(settings_path, existing)
    except OSError as exc:
        raise RuntimeError(
            f"Failed to install hooks: could not write {settings_path}: {exc}"
        ) from exc
    return settings_path


def uninstall_hooks(project_dir: Path) -> Path | None:
    """Remove ButterFence hooks from .claude/settings.local.json."""
    settings_path = project_dir / ".claude" / "settings.local.json"
    if not settings_path.exists():
        return None

    existing = load_json(settings_path)
    if "hooks" not in existing:
        return None

    for event_name in ("PreToolUse", "PostToolUse"):
        if event_name in existing["hooks"]:
            existing["hooks"][event_name] = _remove_butterfence_hooks(
                existing["hooks"][event_name]
            )
            if not existing["hooks"][event_name]:
                del existing["hooks"][event_name]

    if not existing["hooks"]:
        del existing["hooks"]

    save_json(settings_path, existing)
    return settings_path
