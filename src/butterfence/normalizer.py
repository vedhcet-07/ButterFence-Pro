"""Command normalization for pre-matching processing."""

from __future__ import annotations

import re
import shlex


def normalize_command(cmd: str) -> str:
    """Normalize a shell command for matching.

    - Collapse multiple whitespace to single spaces
    - Strip leading/trailing whitespace
    - Resolve common escape sequences
    """
    # Collapse whitespace
    result = re.sub(r"\s+", " ", cmd.strip())
    return result


def split_commands(cmd: str) -> list[str]:
    """Split a compound command on ;, &&, ||, | respecting quotes.

    Returns individual commands for separate matching.
    """
    # Use a simple state machine to split on unquoted delimiters
    commands: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    chars = cmd

    while i < len(chars):
        ch = chars[i]

        # Handle escapes
        if ch == "\\" and i + 1 < len(chars) and not in_single:
            current.append(ch)
            current.append(chars[i + 1])
            i += 2
            continue

        # Toggle quotes
        if ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
            i += 1
            continue

        # Split on delimiters only when not inside quotes
        if not in_single and not in_double:
            # Check for && and ||
            if ch in ("&", "|") and i + 1 < len(chars) and chars[i + 1] == ch:
                part = "".join(current).strip()
                if part:
                    commands.append(part)
                current = []
                i += 2
                continue
            # Check for single ; or |
            if ch == ";":
                part = "".join(current).strip()
                if part:
                    commands.append(part)
                current = []
                i += 1
                continue
            if ch == "|":
                part = "".join(current).strip()
                if part:
                    commands.append(part)
                current = []
                i += 1
                continue

        current.append(ch)
        i += 1

    part = "".join(current).strip()
    if part:
        commands.append(part)

    return commands
