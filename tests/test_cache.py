"""Tests for rule compilation cache."""
import pytest
from butterfence.cache import get_compiled_rules, clear_cache
from butterfence.config import DEFAULT_CONFIG


class TestCache:
    def setup_method(self):
        clear_cache()

    def test_returns_compiled_rules(self):
        rules = get_compiled_rules(DEFAULT_CONFIG)
        assert len(rules) > 0

    def test_cache_hit(self):
        rules1 = get_compiled_rules(DEFAULT_CONFIG)
        rules2 = get_compiled_rules(DEFAULT_CONFIG)
        assert rules1 is rules2  # Same object from cache

    def test_cache_miss_on_change(self):
        rules1 = get_compiled_rules(DEFAULT_CONFIG)
        modified = DEFAULT_CONFIG.copy()
        modified["categories"] = {**DEFAULT_CONFIG["categories"], "new": {"enabled": True, "severity": "low", "action": "warn", "patterns": ["test"], "safe_list": []}}
        rules2 = get_compiled_rules(modified)
        assert rules1 is not rules2

    def test_clear_cache(self):
        rules1 = get_compiled_rules(DEFAULT_CONFIG)
        clear_cache()
        rules2 = get_compiled_rules(DEFAULT_CONFIG)
        assert rules1 is not rules2  # Different object after clearing

    def test_disabled_category_excluded(self):
        config = {"categories": {"test": {"enabled": False, "severity": "high", "action": "block", "patterns": ["test_pattern"], "safe_list": []}}}
        rules = get_compiled_rules(config)
        assert len(rules) == 0
