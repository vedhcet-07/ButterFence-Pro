"""False-positive whitelist engine — .butterfence.yaml glob-based whitelisting."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Default file extensions that are always whitelisted for entropy checks
DEFAULT_WHITELISTED_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".markdown", ".rst", ".txt",
})

WHITELIST_FILENAME = ".butterfence.yaml"


@dataclass
class WhitelistConfig:
    """Parsed whitelist configuration."""
    file_patterns: list[str] = field(default_factory=list)
    path_patterns: list[str] = field(default_factory=list)
    categories_disabled: list[str] = field(default_factory=list)
    entropy_skip_patterns: list[str] = field(default_factory=list)


def load_whitelist(project_dir: Path | None = None) -> WhitelistConfig:
    """Load whitelist config from .butterfence.yaml in the project directory.

    If the file doesn't exist, returns an empty whitelist (nothing whitelisted).
    """
    search_dir = project_dir or Path.cwd()
    config_path = search_dir / WHITELIST_FILENAME

    if not config_path.exists():
        return WhitelistConfig()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse %s: %s", config_path, exc)
        return WhitelistConfig()

    if not isinstance(data, dict):
        logger.warning("%s is not a valid YAML mapping", config_path)
        return WhitelistConfig()

    whitelist_section = data.get("whitelist", {})
    if not isinstance(whitelist_section, dict):
        # Support shorthand: whitelist: ["*.md", "*.txt"]
        if isinstance(whitelist_section, list):
            return WhitelistConfig(file_patterns=_ensure_str_list(whitelist_section))
        return WhitelistConfig()

    return WhitelistConfig(
        file_patterns=_ensure_str_list(whitelist_section.get("files", [])),
        path_patterns=_ensure_str_list(whitelist_section.get("paths", [])),
        categories_disabled=_ensure_str_list(whitelist_section.get("disable_categories", [])),
        entropy_skip_patterns=_ensure_str_list(whitelist_section.get("entropy_skip", [])),
    )


def _ensure_str_list(value: Any) -> list[str]:
    """Coerce a value to a list of strings safely."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def is_file_whitelisted(
    file_path: str,
    whitelist: WhitelistConfig,
) -> bool:
    """Check if a file path matches any whitelist glob pattern.

    Matches against both file_patterns (filename only) and
    path_patterns (full path).
    """
    if not file_path:
        return False

    path = Path(file_path)
    filename = path.name

    # Check filename-based patterns (e.g., "*.md", "README.*")
    for pattern in whitelist.file_patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
        # Also try full path match
        if fnmatch.fnmatch(file_path, pattern):
            return True

    # Check full-path patterns (e.g., "docs/**", "tests/**/fixtures/*")
    normalized = file_path.replace("\\", "/")
    for pattern in whitelist.path_patterns:
        norm_pattern = pattern.replace("\\", "/")
        if fnmatch.fnmatch(normalized, norm_pattern):
            return True

    return False


def is_category_disabled(
    category: str,
    whitelist: WhitelistConfig,
) -> bool:
    """Check if a threat category is disabled in the whitelist."""
    return category in whitelist.categories_disabled


def should_skip_entropy(
    file_path: str,
    whitelist: WhitelistConfig,
) -> bool:
    """Check if entropy checks should be skipped for this file.

    Checks both the explicit entropy_skip patterns and the default
    whitelisted extensions.
    """
    if not file_path:
        return False

    path = Path(file_path)

    # Check default extensions
    if path.suffix.lower() in DEFAULT_WHITELISTED_EXTENSIONS:
        return True

    filename = path.name
    normalized = file_path.replace("\\", "/")

    # Check entropy_skip patterns
    for pattern in whitelist.entropy_skip_patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
        if fnmatch.fnmatch(normalized, pattern.replace("\\", "/")):
            return True

    return False
