"""API key authentication middleware for ButterFence API."""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import Enum

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader


class Role(str, Enum):
    """User roles for access control."""
    ADMIN = "admin"
    DEVELOPER = "developer"


# API key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Environment variable for the API key
API_KEY_ENV = "BUTTERFENCE_API_KEY"

# Default key for development (should be overridden in production)
DEFAULT_DEV_KEY = "bf-dev-key-change-me"


def _get_valid_api_key() -> str:
    """Get the configured API key from environment or default."""
    return os.environ.get(API_KEY_ENV, DEFAULT_DEV_KEY)


def _verify_key(provided: str, expected: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(
        hashlib.sha256(provided.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )


async def require_api_key(
    api_key: str | None = Security(api_key_header),
) -> str:
    """Dependency that requires a valid API key.

    Returns the validated key string.
    """
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header.",
        )

    valid_key = _get_valid_api_key()
    if not _verify_key(api_key, valid_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )

    return api_key


async def require_admin(
    api_key: str = Depends(require_api_key),
) -> str:
    """Dependency that requires admin role.

    For now, any valid API key is treated as admin.
    Role-based access can be expanded later with a key-to-role mapping.
    """
    # In a production system, you'd look up the role for this key
    # For now, all authenticated users have admin access
    return api_key


def get_optional_api_key(
    api_key: str | None = Security(api_key_header),
) -> str | None:
    """Optional API key — allows unauthenticated access but records the key if provided."""
    if api_key is None:
        return None

    valid_key = _get_valid_api_key()
    if _verify_key(api_key, valid_key):
        return api_key
    return None
