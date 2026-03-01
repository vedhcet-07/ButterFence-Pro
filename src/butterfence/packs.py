"""Community rule pack manager — `butterfence pack`."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from butterfence.config import load_config, save_config

logger = logging.getLogger(__name__)

PACKS_DIR = Path(__file__).parent.parent.parent / "assets" / "packs"


@dataclass
class PackInfo:
    name: str
    version: str
    author: str
    description: str
    categories: dict
    file_path: Path


def list_packs(packs_dir: Path | None = None) -> list[PackInfo]:
    """List all available rule packs."""
    search_dir = packs_dir or PACKS_DIR
    if not search_dir.exists():
        return []

    packs: list[PackInfo] = []
    for f in sorted(search_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            packs.append(
                PackInfo(
                    name=data.get("name", f.stem),
                    version=data.get("version", "0.0.0"),
                    author=data.get("author", "unknown"),
                    description=data.get("description", ""),
                    categories=data.get("categories", {}),
                    file_path=f,
                )
            )
        except (yaml.YAMLError, OSError):
            continue
    return packs


def get_pack_info(name: str, packs_dir: Path | None = None) -> PackInfo | None:
    """Get info for a specific pack by name."""
    for pack in list_packs(packs_dir):
        if pack.name == name:
            return pack
    return None



def _validate_pack_patterns(pack_categories: dict) -> list[str]:
    """Validate all regex patterns in a pack. Returns list of errors."""
    errors = []
    for cat_name, cat_config in pack_categories.items():
        for i, pattern in enumerate(cat_config.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{cat_name} pattern[{i}]: {exc}")
    return errors


def install_pack(
    name: str,
    project_dir: Path,
    packs_dir: Path | None = None,
) -> bool:
    """Install a rule pack by merging its categories into config.

    Returns True if successful, False if pack not found.
    Idempotent: installing the same pack twice doesn't duplicate patterns.
    """
    pack = get_pack_info(name, packs_dir)
    if not pack:
        return False

    errors = _validate_pack_patterns(pack.categories)
    if errors:
        logger.warning("Pack '%s' has invalid patterns: %s", name, errors)
        # Still install but skip bad patterns

    config = load_config(project_dir)

    # Merge pack categories into config
    categories = config.get("categories", {})
    for cat_name, cat_config in pack.categories.items():
        if cat_name in categories:
            # Merge patterns without duplicating
            existing_patterns = set(categories[cat_name].get("patterns", []))
            for p in cat_config.get("patterns", []):
                if p not in existing_patterns:
                    categories[cat_name].setdefault("patterns", []).append(p)
                    existing_patterns.add(p)
        else:
            categories[cat_name] = cat_config

    config["categories"] = categories

    # Track installed packs
    installed = config.get("installed_packs", [])
    if name not in installed:
        installed.append(name)
    config["installed_packs"] = installed

    save_config(config, project_dir)
    return True
