"""Secure API key management for ButterFence.

Handles storage, validation, masking, and retrieval of Anthropic API
keys.  Keys are persisted in the user home directory (never inside the
project tree) with restrictive file permissions.

Lookup order used by ``get_api_key()``:
  1. ``ANTHROPIC_API_KEY`` environment variable
  2. Stored key file (``~/.butterfence/api_key``)
  3. Raise ``APIKeyMissingError``
"""

from __future__ import annotations

import logging
import os
import platform
import re
import stat
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

IS_WINDOWS: bool = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class APIKeyMissingError(Exception):
    """Raised when no Anthropic API key can be found."""


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_KEY_DIR_NAME = ".butterfence"
_KEY_FILE_NAME = "api_key"


def get_key_path() -> Path:
    """Return the path to the stored API key file.

    The key is stored under the user home directory at
    ``~/.butterfence/api_key``.  This keeps it outside any project
    repository to prevent accidental commits.
    """
    return Path.home() / _KEY_DIR_NAME / _KEY_FILE_NAME


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Minimum acceptable length for an API key.
_MIN_KEY_LENGTH = 20

# Characters permitted in a valid key string.
_KEY_CHAR_RE = re.compile(r"^[A-Za-z0-9\-_]+$")


def validate_key_format(key: str) -> bool:
    """Check whether *key* looks like a valid Anthropic API key.

    Valid prefixes:
      * ``sk-ant-`` (standard Anthropic prefix)
      * ``sk-`` (short form)

    Additionally the key must be at least 20 characters long and
    contain only alphanumeric characters, hyphens, and underscores.
    """
    if not key or len(key) < _MIN_KEY_LENGTH:
        return False
    if not key.startswith("sk-"):
        return False
    if not _KEY_CHAR_RE.match(key):
        return False
    return True


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


def mask_key(key: str) -> str:
    """Return a masked representation of *key* safe for display.

    Shows the first 7 characters and the last 4, separated by ``****``.
    For very short keys the raw value is fully replaced with asterisks.

    Example::

        sk-ant-abc...rest -> sk-ant-a****est1
    """
    if len(key) <= 11:
        return "*" * len(key)
    return key[:7] + "****" + key[-4:]


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def _set_permissions(path: Path) -> None:
    """Apply restrictive permissions to the key file.

    On Unix-like systems this sets mode 0o600 (owner read/write only).
    On Windows it uses ``icacls`` to remove inherited permissions and
    grant read/write access only to the current user.
    """
    if IS_WINDOWS:
        try:
            user = os.getlogin()
            subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{user}:(R,W)",
                ],
                capture_output=True,
                check=False,
            )
        except OSError:
            # Best-effort; log nothing about the key itself.
            pass
    else:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)


def check_key_permissions(path: Path) -> list[str]:
    """Check whether *path* has appropriately restrictive permissions.

    Returns a list of human-readable warnings.  An empty list means the
    permissions look fine.
    """
    warnings: list[str] = []

    if not path.exists():
        warnings.append(f"Key file does not exist: {path}")
        return warnings

    if IS_WINDOWS:
        # On Windows we only perform a basic readability check.
        if not os.access(str(path), os.R_OK):
            warnings.append(f"Key file is not readable: {path}")
        return warnings

    # Unix permission checks.
    try:
        mode = path.stat().st_mode
        if mode & stat.S_IRGRP:
            warnings.append("Key file is readable by group.")
        if mode & stat.S_IROTH:
            warnings.append("Key file is readable by others.")
        if mode & stat.S_IWGRP:
            warnings.append("Key file is writable by group.")
        if mode & stat.S_IWOTH:
            warnings.append("Key file is writable by others.")
    except OSError as exc:
        warnings.append(f"Could not stat key file: {exc}")

    return warnings


# ---------------------------------------------------------------------------
# Storage operations
# ---------------------------------------------------------------------------


def save_key(key: str) -> Path:
    """Validate and securely persist an API key.

    Creates the ``~/.butterfence/`` directory if it does not exist,
    writes the key, and sets restrictive file permissions.

    Returns the :class:`~pathlib.Path` where the key was saved.

    Raises:
        ValueError: If *key* does not pass format validation.
    """
    stripped = key.strip()
    if not validate_key_format(stripped):
        raise ValueError(
            "Invalid API key format. Keys must start with 'sk-', "
            f"be at least {_MIN_KEY_LENGTH} characters, and contain "
            "only letters, numbers, hyphens, and underscores."
        )

    path = get_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write key to file.
    path.write_text(stripped, encoding="utf-8")
    _set_permissions(path)

    # Do NOT log the key value -- only the storage location.
    logger.info("API key saved to %s", path)
    return path


def load_key() -> str | None:
    """Load the stored API key from disk.

    Returns ``None`` if the file does not exist or cannot be read.
    Emits a warning if the file permissions are too permissive.
    """
    path = get_key_path()
    if not path.exists():
        return None

    # Warn about lax permissions but still load the key.
    perm_warnings = check_key_permissions(path)
    for warning in perm_warnings:
        logger.warning("Key file permission issue: %s", warning)

    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if not value:
        return None

    return value


def remove_key() -> bool:
    """Securely remove the stored API key.

    Overwrites the file content with null bytes before unlinking to
    reduce the chance of key recovery from disk.

    Returns ``True`` if the file was removed, ``False`` if it did not
    exist.
    """
    path = get_key_path()
    if not path.exists():
        return False

    try:
        # Overwrite with zeros before deleting.
        size = path.stat().st_size
        path.write_bytes(b"\x00" * size)
        path.unlink()
    except OSError:
        # If overwrite fails, still try to remove.
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    logger.info("API key removed from %s", path)
    return True


# ---------------------------------------------------------------------------
# Unified retrieval
# ---------------------------------------------------------------------------


def get_api_key() -> str:
    """Return the Anthropic API key from the best available source.

    Lookup order:

    1. ``ANTHROPIC_API_KEY`` environment variable.
    2. Stored key file at ``~/.butterfence/api_key``.
    3. Raise :exc:`APIKeyMissingError` with a helpful message.

    This function is the single source of truth for API key retrieval
    across the entire ButterFence codebase.
    """
    # 1. Environment variable.
    env_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env_key:
        return env_key

    # 2. Stored key file.
    stored = load_key()
    if stored:
        return stored

    # 3. Nothing found.
    raise APIKeyMissingError(
        "No Anthropic API key found. Provide one via:\n"
        "  1. Environment variable:  export ANTHROPIC_API_KEY='your-key'\n"
        "  2. Stored key file:       butterfence auth save <key>\n"
        "     (saves to ~/.butterfence/api_key with restricted permissions)"
    )


# ---------------------------------------------------------------------------
# Gemini API key management
# ---------------------------------------------------------------------------

_GEMINI_KEY_FILE_NAME = "gemini_api_key"


def get_gemini_key_path() -> Path:
    """Return the path to the stored Gemini API key file."""
    return Path.home() / _KEY_DIR_NAME / _GEMINI_KEY_FILE_NAME


def save_gemini_key(key: str) -> Path:
    """Validate and securely persist a Gemini API key.

    Returns the Path where the key was saved.

    Raises:
        ValueError: If the key is empty or too short.
    """
    stripped = key.strip()
    if not stripped or len(stripped) < 10:
        raise ValueError(
            "Invalid Gemini API key. Key must be at least 10 characters."
        )

    path = get_gemini_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stripped, encoding="utf-8")
    _set_permissions(path)

    logger.info("Gemini API key saved to %s", path)
    return path


def load_gemini_key() -> str | None:
    """Load the stored Gemini API key from disk."""
    path = get_gemini_key_path()
    if not path.exists():
        return None

    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    return value if value else None


def get_gemini_api_key() -> str:
    """Return the Gemini API key from the best available source.

    Lookup order:
    1. GOOGLE_API_KEY environment variable.
    2. GEMINI_API_KEY environment variable.
    3. Stored key file at ~/.butterfence/gemini_api_key.
    4. Raise APIKeyMissingError.
    """
    for env_var in ("GOOGLE_API_KEY", "GEMINI_API_KEY"):
        val = os.environ.get(env_var, "").strip()
        if val:
            return val

    stored = load_gemini_key()
    if stored:
        return stored

    raise APIKeyMissingError(
        "No Google/Gemini API key found. Provide one via:\n"
        "  1. Environment variable:  export GOOGLE_API_KEY='your-key'\n"
        "  2. Environment variable:  export GEMINI_API_KEY='your-key'\n"
        "  3. Stored key file:       butterfence auth save-gemini <key>"
    )

