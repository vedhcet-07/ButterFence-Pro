"""Obfuscation detection — base64, hex, variable indirection."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass
class ObfuscationFinding:
    technique: str
    original_text: str
    decoded_text: str
    offset: int


def detect_base64_commands(text: str) -> list[ObfuscationFinding]:
    """Detect base64-encoded command execution patterns.

    Catches: echo BASE64 | base64 -d | sh
             echo BASE64 | base64 --decode | bash
    """
    findings: list[ObfuscationFinding] = []
    # Pattern: echo <base64> | base64 -d | sh/bash
    pattern = re.compile(
        r"echo\s+([A-Za-z0-9+/=]{4,})\s*\|\s*base64\s+(?:-d|--decode)",
        re.IGNORECASE,
    )
    for m in pattern.finditer(text):
        b64_str = m.group(1)
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
        except Exception:
            decoded = "<decode-failed>"
        findings.append(
            ObfuscationFinding(
                technique="base64",
                original_text=m.group(0),
                decoded_text=decoded,
                offset=m.start(),
            )
        )
    return findings


def detect_hex_escaping(text: str) -> list[ObfuscationFinding]:
    r"""Detect hex escape sequences that could hide commands.

    Catches: \x72\x6d (rm), $'\x72\x6d' etc.
    """
    findings: list[ObfuscationFinding] = []
    # Find sequences of 2+ hex escapes
    pattern = re.compile(r"((?:\\x[0-9a-fA-F]{2}){2,})")
    for m in pattern.finditer(text):
        hex_str = m.group(1)
        try:
            decoded = re.sub(
                r"\\x([0-9a-fA-F]{2})",
                lambda h: chr(int(h.group(1), 16)),
                hex_str,
            )
        except Exception:
            decoded = "<decode-failed>"
        findings.append(
            ObfuscationFinding(
                technique="hex_escape",
                original_text=hex_str,
                decoded_text=decoded,
                offset=m.start(),
            )
        )
    return findings


def detect_variable_indirection(text: str) -> list[ObfuscationFinding]:
    """Detect variable-based command indirection.

    Catches: a=rm; $a -rf /
             cmd=curl; $cmd http://evil.com
    """
    findings: list[ObfuscationFinding] = []
    # Pattern: var=value followed by $var usage
    assign_pattern = re.compile(r"\b([a-zA-Z_]\w*)=([\w/.\-]+)")
    assignments = {m.group(1): m.group(2) for m in assign_pattern.finditer(text)}

    for var_name, value in assignments.items():
        usage_pattern = re.compile(r"\$" + re.escape(var_name) + r"\b")
        for m in usage_pattern.finditer(text):
            findings.append(
                ObfuscationFinding(
                    technique="variable_indirection",
                    original_text=f"${var_name}",
                    decoded_text=value,
                    offset=m.start(),
                )
            )
    return findings


def detect_backtick_substitution(text: str) -> list[ObfuscationFinding]:
    """Detect backtick command substitution used for obfuscation."""
    findings: list[ObfuscationFinding] = []
    pattern = re.compile(r"`([^`]+)`")
    for m in pattern.finditer(text):
        inner = m.group(1)
        findings.append(
            ObfuscationFinding(
                technique="backtick_substitution",
                original_text=m.group(0),
                decoded_text=inner,
                offset=m.start(),
            )
        )
    return findings


def detect_obfuscation(text: str) -> list[ObfuscationFinding]:
    """Run all obfuscation detectors and return combined findings."""
    findings: list[ObfuscationFinding] = []
    findings.extend(detect_base64_commands(text))
    findings.extend(detect_hex_escaping(text))
    findings.extend(detect_variable_indirection(text))
    findings.extend(detect_backtick_substitution(text))
    return findings
