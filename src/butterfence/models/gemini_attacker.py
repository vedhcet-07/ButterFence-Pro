"""Google Gemini attacker — generates adversarial scenarios via Gemini API."""

from __future__ import annotations

import logging
import os

from butterfence.models.base import AttackerResult, BaseAttacker
from butterfence.redteam import APICallError, RedTeamError

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


def _get_gemini_api_key() -> str:
    """Retrieve the Google/Gemini API key.

    Checks GOOGLE_API_KEY env var first, then GEMINI_API_KEY,
    then the stored key file at ~/.butterfence/gemini_api_key.
    """
    for env_var in ("GOOGLE_API_KEY", "GEMINI_API_KEY"):
        key = os.environ.get(env_var, "").strip()
        if key:
            return key

    # Check stored key file
    from pathlib import Path
    key_path = Path.home() / ".butterfence" / "gemini_api_key"
    if key_path.exists():
        try:
            stored = key_path.read_text(encoding="utf-8").strip()
            if stored:
                return stored
        except OSError:
            pass

    raise RedTeamError(
        "No Google/Gemini API key found. Provide one via:\n"
        "  1. Environment variable:  export GOOGLE_API_KEY='your-key'\n"
        "  2. Environment variable:  export GEMINI_API_KEY='your-key'\n"
        "  3. Stored key file:       butterfence auth save-gemini <key>"
    )


class GeminiAttacker(BaseAttacker):
    """Red-team attacker powered by Google Gemini models."""

    @property
    def provider_name(self) -> str:
        return "Google"

    @property
    def default_model(self) -> str:
        return DEFAULT_GEMINI_MODEL

    def check_api_key(self) -> bool:
        """Check if Gemini API key is available."""
        try:
            _get_gemini_api_key()
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
        """Call Gemini to generate adversarial scenarios."""
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise RedTeamError(
                "The 'google-generativeai' package is required for Gemini red-team. "
                "Install it with: pip install google-generativeai"
            ) from exc

        api_key = _get_gemini_api_key()
        genai.configure(api_key=api_key)

        used_model = model or self.default_model
        logger.info(
            "GeminiAttacker: calling %s (max_tokens=%d)", used_model, max_tokens
        )

        try:
            gm = genai.GenerativeModel(
                model_name=used_model,
                system_instruction=system_prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.9,
                ),
            )

            response = gm.generate_content(user_prompt)
        except Exception as exc:
            # Catch all Gemini-specific errors
            exc_name = type(exc).__name__
            if "AuthenticationError" in exc_name or "InvalidArgument" in exc_name:
                raise APICallError(
                    "Gemini authentication failed. Check your GOOGLE_API_KEY."
                ) from exc
            elif "ResourceExhausted" in exc_name or "429" in str(exc):
                raise APICallError(
                    "Gemini rate limit exceeded. Wait a moment and try again."
                ) from exc
            else:
                raise APICallError(
                    f"Gemini API error ({exc_name}): {exc}"
                ) from exc

        # Extract text from response
        try:
            raw_text = response.text
        except (ValueError, AttributeError):
            # Some responses may be blocked by safety filters
            raw_text = ""
            if hasattr(response, "candidates") and response.candidates:
                for candidate in response.candidates:
                    if hasattr(candidate, "content") and candidate.content:
                        for part in candidate.content.parts:
                            if hasattr(part, "text"):
                                raw_text += part.text

        if not raw_text.strip():
            raise APICallError(
                "Gemini returned empty response (possibly blocked by safety filters)."
            )

        usage = None
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            meta = response.usage_metadata
            usage = {
                "input_tokens": getattr(meta, "prompt_token_count", 0),
                "output_tokens": getattr(meta, "candidates_token_count", 0),
            }

        return AttackerResult(
            raw_text=raw_text,
            model_name=used_model,
            provider="google",
            token_usage=usage,
        )
