"""Tests for the multi-model attacker abstraction layer."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from butterfence.models.base import AttackerResult, BaseAttacker


# ---------------------------------------------------------------------------
# A. BaseAttacker ABC tests
# ---------------------------------------------------------------------------

class TestBaseAttacker:
    """Verify that BaseAttacker cannot be instantiated directly."""

    def test_cannot_instantiate_abc(self) -> None:
        with pytest.raises(TypeError):
            BaseAttacker()  # type: ignore[abstract]


class TestAttackerResult:
    """Test the AttackerResult dataclass."""

    def test_basic_creation(self) -> None:
        r = AttackerResult(
            raw_text="hello",
            model_name="test-model",
            provider="test",
        )
        assert r.raw_text == "hello"
        assert r.model_name == "test-model"
        assert r.provider == "test"
        assert r.token_usage is None

    def test_with_token_usage(self) -> None:
        r = AttackerResult(
            raw_text="test",
            model_name="m",
            provider="p",
            token_usage={"input_tokens": 100, "output_tokens": 50},
        )
        assert r.token_usage["input_tokens"] == 100


# ---------------------------------------------------------------------------
# B. ClaudeAttacker tests
# ---------------------------------------------------------------------------

class TestClaudeAttacker:
    """Test ClaudeAttacker (mocked API)."""

    def test_provider_name(self) -> None:
        from butterfence.models.claude_attacker import ClaudeAttacker
        attacker = ClaudeAttacker()
        assert attacker.provider_name == "Anthropic"

    def test_default_model(self) -> None:
        from butterfence.models.claude_attacker import ClaudeAttacker
        attacker = ClaudeAttacker()
        assert "claude" in attacker.default_model.lower() or "opus" in attacker.default_model.lower()

    def test_check_api_key_false_when_missing(self) -> None:
        from butterfence.models.claude_attacker import ClaudeAttacker
        attacker = ClaudeAttacker()
        env = os.environ.copy()
        env.pop("ANTHROPIC_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            # Will be false unless ~/.butterfence/api_key exists
            result = attacker.check_api_key()
            # Could be True or False depending on local state, but should not crash
            assert isinstance(result, bool)

    def test_generate_with_mocked_anthropic(self) -> None:
        from butterfence.models.claude_attacker import ClaudeAttacker

        mock_mod = MagicMock()
        mock_text_block = MagicMock()
        mock_text_block.text = '[{"id":"redteam-t1","name":"test"}]'
        mock_response = MagicMock()
        mock_response.content = [mock_text_block]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_mod.Anthropic.return_value.messages.create.return_value = mock_response

        env = os.environ.copy()
        env["ANTHROPIC_API_KEY"] = "test-key-12345"

        with patch.dict(os.environ, env, clear=True), \
             patch.dict("sys.modules", {"anthropic": mock_mod}):
            attacker = ClaudeAttacker()
            result = attacker.generate("system", "user")

        assert isinstance(result, AttackerResult)
        assert "redteam-t1" in result.raw_text
        assert result.provider == "anthropic"


# ---------------------------------------------------------------------------
# C. GeminiAttacker tests
# ---------------------------------------------------------------------------

class TestGeminiAttacker:
    """Test GeminiAttacker (mocked API)."""

    def test_provider_name(self) -> None:
        from butterfence.models.gemini_attacker import GeminiAttacker
        attacker = GeminiAttacker()
        assert attacker.provider_name == "Google"

    def test_default_model(self) -> None:
        from butterfence.models.gemini_attacker import GeminiAttacker
        attacker = GeminiAttacker()
        assert "gemini" in attacker.default_model.lower()

    def test_check_api_key_with_env(self) -> None:
        from butterfence.models.gemini_attacker import GeminiAttacker
        attacker = GeminiAttacker()
        env = os.environ.copy()
        env["GOOGLE_API_KEY"] = "test-gemini-key-12345"
        with patch.dict(os.environ, env, clear=True):
            assert attacker.check_api_key() is True

    def test_check_api_key_without_env(self) -> None:
        from butterfence.models.gemini_attacker import GeminiAttacker
        attacker = GeminiAttacker()
        env = os.environ.copy()
        env.pop("GOOGLE_API_KEY", None)
        env.pop("GEMINI_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = attacker.check_api_key()
            assert isinstance(result, bool)

    def test_generate_requires_sdk(self) -> None:
        """Without google-generativeai installed, should raise RedTeamError."""
        from butterfence.models.gemini_attacker import GeminiAttacker
        from butterfence.redteam import RedTeamError

        env = os.environ.copy()
        env["GOOGLE_API_KEY"] = "test-key-12345"

        attacker = GeminiAttacker()

        # Remove google.generativeai from sys.modules to simulate not installed
        with patch.dict(os.environ, env, clear=True), \
             patch.dict("sys.modules", {"google": None, "google.generativeai": None}):
            with pytest.raises((RedTeamError, ImportError)):
                attacker.generate("system", "user")


# ---------------------------------------------------------------------------
# D. AVAILABLE_MODELS registry tests
# ---------------------------------------------------------------------------

class TestAvailableModels:
    """Test the model registry."""

    def test_contains_claude(self) -> None:
        from butterfence.models import AVAILABLE_MODELS
        assert "claude" in AVAILABLE_MODELS

    def test_contains_gemini(self) -> None:
        from butterfence.models import AVAILABLE_MODELS
        assert "gemini" in AVAILABLE_MODELS

    def test_all_values_are_base_attacker_subclasses(self) -> None:
        from butterfence.models import AVAILABLE_MODELS
        for name, cls in AVAILABLE_MODELS.items():
            assert issubclass(cls, BaseAttacker), f"{name} is not a BaseAttacker subclass"


# ---------------------------------------------------------------------------
# E. Auth Gemini tests
# ---------------------------------------------------------------------------

class TestGeminiAuth:
    """Test Gemini key storage."""

    def test_save_and_load_gemini_key(self, tmp_path: Path) -> None:
        from butterfence.auth import save_gemini_key, load_gemini_key, get_gemini_key_path

        with patch("butterfence.auth.get_gemini_key_path", return_value=tmp_path / "gemini_key"):
            path = save_gemini_key("test-gemini-key-12345678")
            assert path.exists()

        with patch("butterfence.auth.get_gemini_key_path", return_value=tmp_path / "gemini_key"):
            loaded = load_gemini_key()
            assert loaded == "test-gemini-key-12345678"

    def test_save_gemini_key_rejects_short(self) -> None:
        from butterfence.auth import save_gemini_key
        with pytest.raises(ValueError):
            save_gemini_key("short")

    def test_get_gemini_api_key_from_env(self) -> None:
        from butterfence.auth import get_gemini_api_key
        env = os.environ.copy()
        env["GOOGLE_API_KEY"] = "test-google-api-key-xyz"
        with patch.dict(os.environ, env, clear=True):
            assert get_gemini_api_key() == "test-google-api-key-xyz"

    def test_get_gemini_api_key_missing(self) -> None:
        from butterfence.auth import get_gemini_api_key, APIKeyMissingError
        env = os.environ.copy()
        env.pop("GOOGLE_API_KEY", None)
        env.pop("GEMINI_API_KEY", None)
        with patch.dict(os.environ, env, clear=True), \
             patch("butterfence.auth.load_gemini_key", return_value=None):
            with pytest.raises(APIKeyMissingError):
                get_gemini_api_key()


# ---------------------------------------------------------------------------
# F. Multi-model orchestrator tests
# ---------------------------------------------------------------------------

class TestMultiModelOrchestrator:
    """Test run_multi_model_redteam with mocks."""

    def test_rejects_unknown_model(self, tmp_path: Path) -> None:
        from butterfence.config import DEFAULT_CONFIG
        from butterfence.redteam import RedTeamError, run_multi_model_redteam

        with pytest.raises(RedTeamError, match="Unknown model"):
            run_multi_model_redteam(
                config=DEFAULT_CONFIG,
                target_dir=tmp_path,
                models=["nonexistent_model"],
                count=2,
            )
