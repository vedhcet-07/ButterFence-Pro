"""Claude (Anthropic) attacker — wraps the existing Anthropic API logic."""

from __future__ import annotations

import logging

from butterfence.models.base import AttackerResult, BaseAttacker
from butterfence.redteam import APICallError, RedTeamError

logger = logging.getLogger(__name__)

DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"


class ClaudeAttacker(BaseAttacker):
    """Red-team attacker powered by Anthropic Claude models."""

    @property
    def provider_name(self) -> str:
        return "Anthropic"

    @property
    def default_model(self) -> str:
        return DEFAULT_CLAUDE_MODEL

    def check_api_key(self) -> bool:
        """Check if Anthropic API key is available."""
        try:
            from butterfence.auth import get_api_key
            get_api_key()
            return True
        except Exception:
            return False

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        model: str | None = None,
        max_tokens: int = 8192,
    ) -> AttackerResult:
        """Call Claude to generate adversarial scenarios."""
        try:
            import anthropic
        except ImportError as exc:
            raise RedTeamError(
                "The 'anthropic' package is required for Claude red-team. "
                "Install it with: pip install anthropic"
            ) from exc

        from butterfence.auth import get_api_key
        api_key = get_api_key()
        client = anthropic.Anthropic(api_key=api_key)

        used_model = model or self.default_model
        logger.info(
            "ClaudeAttacker: calling %s (max_tokens=%d)", used_model, max_tokens
        )

        try:
            response = client.messages.create(
                model=used_model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.AuthenticationError as exc:
            raise APICallError(
                "Claude authentication failed. Check your ANTHROPIC_API_KEY."
            ) from exc
        except anthropic.RateLimitError as exc:
            raise APICallError(
                "Claude rate limit exceeded. Wait a moment and try again."
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise APICallError(
                f"Could not connect to the Anthropic API: {exc}"
            ) from exc
        except anthropic.APIStatusError as exc:
            raise APICallError(
                f"Claude API returned status {exc.status_code}: {exc.message}"
            ) from exc

        # Extract text content
        raw_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                raw_text += block.text

        if not raw_text.strip():
            raise APICallError("Claude returned empty response content.")

        usage = None
        if hasattr(response, "usage") and response.usage:
            usage = {
                "input_tokens": getattr(response.usage, "input_tokens", 0),
                "output_tokens": getattr(response.usage, "output_tokens", 0),
            }

        return AttackerResult(
            raw_text=raw_text,
            model_name=used_model,
            provider="anthropic",
            token_usage=usage,
        )
