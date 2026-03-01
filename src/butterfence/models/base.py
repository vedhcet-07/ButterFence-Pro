"""Base attacker ABC for multi-model red-team support."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AttackerResult:
    """Raw result from an attacker's scenario generation."""
    raw_text: str
    model_name: str
    provider: str
    token_usage: dict | None = None


class BaseAttacker(ABC):
    """Abstract base class for red-team scenario generators.

    Each concrete attacker wraps a specific LLM provider (Anthropic,
    Google, etc.) and exposes a uniform interface for generating
    adversarial scenarios from a system+user prompt pair.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name (e.g. 'Anthropic', 'Google')."""
        ...

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default model identifier for this provider."""
        ...

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model: str | None = None,
        max_tokens: int = 8192,
    ) -> AttackerResult:
        """Generate adversarial scenarios by calling the provider's API.

        Args:
            system_prompt: The red-team system instructions.
            user_prompt: Repo context + generation request.
            model: Override model identifier. If None, uses default_model.
            max_tokens: Max tokens for the response.

        Returns:
            AttackerResult with the raw LLM text output.

        Raises:
            APICallError: If the API call fails.
            RedTeamError: If the provider SDK is not installed.
        """
        ...

    @abstractmethod
    def check_api_key(self) -> bool:
        """Check whether the required API key is available.

        Returns True if the key is configured, False otherwise.
        Does NOT raise exceptions.
        """
        ...
