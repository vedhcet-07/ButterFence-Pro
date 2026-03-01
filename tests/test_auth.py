"""Tests for the butterfence.auth module.

Covers key validation, masking, save/load/remove lifecycle, and the
unified get_api_key() retrieval with env-var vs stored-file precedence.
"""

from __future__ import annotations

import pytest

from butterfence.auth import (
    APIKeyMissingError,
    get_api_key,
    load_key,
    mask_key,
    remove_key,
    save_key,
    validate_key_format,
)


# ── Helpers ─────────────────────────────────────────────────────────


def _make_key(prefix: str = "sk-ant-test-", body_len: int = 20) -> str:
    """Build a syntactically valid test key."""
    return prefix + "a" * body_len


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def key_path(tmp_path, monkeypatch):
    """Redirect the key storage path to a temporary directory."""
    path = tmp_path / "api_key"
    monkeypatch.setattr("butterfence.auth.get_key_path", lambda: path)
    return path


# ── TestValidateKeyFormat ───────────────────────────────────────────


class TestValidateKeyFormat:
    """validate_key_format() checks prefix, length, and charset."""

    def test_valid_key(self):
        key = "sk-ant-" + "a" * 30
        assert validate_key_format(key) is True

    def test_valid_short_prefix(self):
        key = "sk-" + "x" * 20
        assert validate_key_format(key) is True

    def test_rejects_short_key(self):
        assert validate_key_format("sk-abc") is False

    def test_rejects_bad_prefix(self):
        key = "bad-" + "x" * 30
        assert validate_key_format(key) is False


# ── TestMaskKey ─────────────────────────────────────────────────────


class TestMaskKey:
    """mask_key() hides the middle portion of a key string."""

    def test_masks_normal_key(self):
        key = "sk-ant-abcdefghij1234"
        masked = mask_key(key)
        # key[:7] == "sk-ant-", key[-4:] == "1234"
        assert masked == "sk-ant-****1234"

    def test_masks_short_key(self):
        key = "abcdefghij"  # 10 chars, <= 11 threshold
        masked = mask_key(key)
        assert masked == "*" * 10

    def test_masks_exact_boundary(self):
        # 12 chars is the first length that shows prefix + suffix.
        key = "sk-ant-12345"  # 12 chars
        masked = mask_key(key)
        assert masked == "sk-ant-****2345"


# ── TestSaveLoadRemove ──────────────────────────────────────────────


class TestSaveLoadRemove:
    """save_key / load_key / remove_key lifecycle using temp storage."""

    def test_save_and_load(self, key_path):
        key = _make_key()
        save_key(key)
        assert key_path.exists()
        loaded = load_key()
        assert loaded == key

    def test_save_creates_directory(self, tmp_path, monkeypatch):
        nested = tmp_path / "deep" / "nested"
        path = nested / "api_key"
        monkeypatch.setattr("butterfence.auth.get_key_path", lambda: path)

        key = _make_key()
        save_key(key)

        assert nested.exists()
        assert path.exists()
        assert path.read_text(encoding="utf-8") == key

    def test_save_rejects_invalid(self, key_path):
        with pytest.raises(ValueError, match="Invalid API key format"):
            save_key("bad")

    def test_remove_existing_key(self, key_path):
        save_key(_make_key())
        assert key_path.exists()

        result = remove_key()
        assert result is True
        assert not key_path.exists()

    def test_remove_nonexistent(self, key_path):
        assert not key_path.exists()
        result = remove_key()
        assert result is False


# ── TestGetApiKey ───────────────────────────────────────────────────


class TestGetApiKey:
    """get_api_key() prefers env var, falls back to stored key."""

    def test_prefers_env_var(self, key_path, monkeypatch):
        env_key = _make_key(prefix="sk-env-", body_len=20)
        stored_key = _make_key(prefix="sk-stored-", body_len=20)

        monkeypatch.setenv("ANTHROPIC_API_KEY", env_key)
        save_key(stored_key)

        result = get_api_key()
        assert result == env_key

    def test_falls_back_to_stored(self, key_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        stored_key = _make_key(prefix="sk-stored-", body_len=20)
        save_key(stored_key)

        result = get_api_key()
        assert result == stored_key

    def test_raises_when_none(self, key_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(APIKeyMissingError):
            get_api_key()
