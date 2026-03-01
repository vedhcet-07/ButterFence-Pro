"""Rule compilation cache — avoid recompiling rules on every match."""

from __future__ import annotations

import hashlib
import json

from butterfence.rules import CompiledRule, compile_rules

_cache: dict[str, list[CompiledRule]] = {}


def _config_hash(config: dict) -> str:
    """Compute a stable hash of the config categories for caching."""
    categories = config.get("categories", {})
    raw = json.dumps(categories, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()


def get_compiled_rules(config: dict) -> list[CompiledRule]:
    """Return compiled rules, using cache if config hasn't changed."""
    key = _config_hash(config)
    if key in _cache:
        return _cache[key]
    rules = compile_rules(config)
    _cache[key] = rules
    return rules


def clear_cache() -> None:
    """Clear the rule compilation cache."""
    _cache.clear()
