"""Model abstraction layer for multi-model red-team attacks.

Provides a BaseAttacker ABC and concrete implementations for each
supported LLM provider.
"""

from butterfence.models.base import BaseAttacker
from butterfence.models.claude_attacker import ClaudeAttacker
from butterfence.models.gemini_attacker import GeminiAttacker

AVAILABLE_MODELS: dict[str, type[BaseAttacker]] = {
    "claude": ClaudeAttacker,
    "gemini": GeminiAttacker,
}

__all__ = [
    "BaseAttacker",
    "ClaudeAttacker",
    "GeminiAttacker",
    "AVAILABLE_MODELS",
]
