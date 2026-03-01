"""Tests for the false-positive whitelist engine."""

import pytest
from pathlib import Path

from butterfence.whitelist import (
    WhitelistConfig,
    is_category_disabled,
    is_file_whitelisted,
    load_whitelist,
    should_skip_entropy,
)


class TestWhitelistConfig:
    """Test WhitelistConfig dataclass defaults."""

    def test_empty_config(self) -> None:
        wl = WhitelistConfig()
        assert wl.file_patterns == []
        assert wl.path_patterns == []
        assert wl.categories_disabled == []
        assert wl.entropy_skip_patterns == []


class TestIsFileWhitelisted:
    """Test glob pattern matching for file whitelisting."""

    def test_no_patterns_means_not_whitelisted(self) -> None:
        wl = WhitelistConfig()
        assert not is_file_whitelisted("src/main.py", wl)

    def test_extension_pattern_match(self) -> None:
        wl = WhitelistConfig(file_patterns=["*.md"])
        assert is_file_whitelisted("README.md", wl)
        assert is_file_whitelisted("/path/to/docs/guide.md", wl)
        assert not is_file_whitelisted("main.py", wl)

    def test_multiple_patterns(self) -> None:
        wl = WhitelistConfig(file_patterns=["*.md", "*.txt", "*.rst"])
        assert is_file_whitelisted("README.md", wl)
        assert is_file_whitelisted("notes.txt", wl)
        assert is_file_whitelisted("docs.rst", wl)
        assert not is_file_whitelisted("code.py", wl)

    def test_specific_filename_pattern(self) -> None:
        wl = WhitelistConfig(file_patterns=["README.*", "LICENSE"])
        assert is_file_whitelisted("README.md", wl)
        assert is_file_whitelisted("README.txt", wl)
        assert is_file_whitelisted("LICENSE", wl)
        assert not is_file_whitelisted("CONTRIBUTING.md", wl)

    def test_path_pattern_match(self) -> None:
        wl = WhitelistConfig(path_patterns=["docs/*", "tests/fixtures/*"])
        assert is_file_whitelisted("docs/guide.md", wl)
        assert is_file_whitelisted("tests/fixtures/data.json", wl)
        assert not is_file_whitelisted("src/main.py", wl)

    def test_windows_path_normalization(self) -> None:
        wl = WhitelistConfig(path_patterns=["docs/*"])
        assert is_file_whitelisted("docs\\guide.md", wl)

    def test_empty_path_not_whitelisted(self) -> None:
        wl = WhitelistConfig(file_patterns=["*.md"])
        assert not is_file_whitelisted("", wl)


class TestIsCategoryDisabled:
    """Test category disabling via whitelist."""

    def test_no_disabled_categories(self) -> None:
        wl = WhitelistConfig()
        assert not is_category_disabled("destructive_shell", wl)

    def test_disabled_category(self) -> None:
        wl = WhitelistConfig(categories_disabled=["sql_injection", "python_dangerous"])
        assert is_category_disabled("sql_injection", wl)
        assert is_category_disabled("python_dangerous", wl)
        assert not is_category_disabled("destructive_shell", wl)


class TestShouldSkipEntropy:
    """Test entropy skip logic."""

    def test_default_extensions_skipped(self) -> None:
        wl = WhitelistConfig()
        assert should_skip_entropy("README.md", wl)
        assert should_skip_entropy("guide.txt", wl)
        assert should_skip_entropy("docs.rst", wl)

    def test_code_file_not_skipped(self) -> None:
        wl = WhitelistConfig()
        assert not should_skip_entropy("main.py", wl)
        assert not should_skip_entropy("app.js", wl)

    def test_custom_entropy_skip_pattern(self) -> None:
        wl = WhitelistConfig(entropy_skip_patterns=["*.test.js", "*.spec.py"])
        assert should_skip_entropy("component.test.js", wl)
        assert should_skip_entropy("module.spec.py", wl)
        assert not should_skip_entropy("app.js", wl)

    def test_empty_path_not_skipped(self) -> None:
        wl = WhitelistConfig()
        assert not should_skip_entropy("", wl)


class TestLoadWhitelist:
    """Test loading .butterfence.yaml from disk."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        wl = load_whitelist(tmp_path)
        assert wl.file_patterns == []
        assert wl.path_patterns == []

    def test_load_full_config(self, tmp_path: Path) -> None:
        content = """
whitelist:
  files:
    - "*.md"
    - "*.txt"
  paths:
    - "docs/*"
  disable_categories:
    - "sql_injection"
  entropy_skip:
    - "*.test.js"
"""
        (tmp_path / ".butterfence.yaml").write_text(content, encoding="utf-8")
        wl = load_whitelist(tmp_path)
        assert "*.md" in wl.file_patterns
        assert "*.txt" in wl.file_patterns
        assert "docs/*" in wl.path_patterns
        assert "sql_injection" in wl.categories_disabled
        assert "*.test.js" in wl.entropy_skip_patterns

    def test_load_shorthand_list(self, tmp_path: Path) -> None:
        """Support shorthand: whitelist: ["*.md", "*.txt"]"""
        content = """
whitelist:
  - "*.md"
  - "*.txt"
"""
        (tmp_path / ".butterfence.yaml").write_text(content, encoding="utf-8")
        wl = load_whitelist(tmp_path)
        assert "*.md" in wl.file_patterns
        assert "*.txt" in wl.file_patterns

    def test_invalid_yaml_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / ".butterfence.yaml").write_text("{{{{invalid yaml", encoding="utf-8")
        wl = load_whitelist(tmp_path)
        assert wl.file_patterns == []

    def test_non_dict_yaml_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / ".butterfence.yaml").write_text("just a string", encoding="utf-8")
        wl = load_whitelist(tmp_path)
        assert wl.file_patterns == []
