"""Cross-platform path normalization and JSON helpers."""

from __future__ import annotations

import json
from pathlib import Path


def normalize_path(path: str) -> str:
    """Normalize path separators to forward slashes and expand ~ to home."""
    return path.replace("\\", "/")


def load_json(path: Path) -> dict:
    """Load a JSON file, returning empty dict if missing or malformed."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path: Path, data: dict) -> None:
    """Save dict as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result
