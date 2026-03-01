"""Shannon entropy secret detection."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass
class EntropyFinding:
    text: str
    entropy: float
    offset: int
    length: int


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


def find_high_entropy_strings(
    text: str, threshold: float = 4.5, min_length: int = 16
) -> list[EntropyFinding]:
    """Find high-entropy substrings that may be secrets.

    Scans for contiguous non-whitespace tokens >= min_length
    and returns those with entropy above threshold.
    """
    findings: list[EntropyFinding] = []
    # Match tokens of alphanumeric + common secret chars
    token_re = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % min_length)
    for m in token_re.finditer(text):
        token = m.group()
        ent = shannon_entropy(token)
        if ent >= threshold:
            findings.append(
                EntropyFinding(
                    text=token,
                    entropy=round(ent, 3),
                    offset=m.start(),
                    length=len(token),
                )
            )
    return findings
