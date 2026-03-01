"""Behavioral attack chain detection -- multi-step pattern matching."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ChainStep:
    pattern: str
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class ChainDefinition:
    id: str
    name: str
    steps: list[ChainStep]
    window_seconds: int = 300
    severity: str = "critical"
    description: str = ""


@dataclass
class ChainMatch:
    chain_id: str
    chain_name: str
    completed_steps: list[str]
    severity: str


DEFAULT_CHAINS: list[dict] = [
    {
        "id": "exfil-env",
        "name": "Environment file exfiltration",
        "steps": [r"\.env", r"curl\s+.*(-d|--data|POST)"],
        "window_seconds": 300,
        "severity": "critical",
        "description": "Reading .env then sending data via curl suggests exfiltration",
    },
    {
        "id": "exfil-creds",
        "name": "Credential exfiltration via SSH",
        "steps": [r"(credentials|id_rsa|\\.pem)", r"ssh\s+.*@"],
        "window_seconds": 300,
        "severity": "critical",
        "description": "Accessing credentials then SSH-ing to external server",
    },
]


class ChainDetector:
    """Stateful detector that tracks in-progress attack chains across events."""

    def __init__(
        self,
        chains: list[dict] | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.chains: list[ChainDefinition] = []
        for c in chains or DEFAULT_CHAINS:
            self.chains.append(
                ChainDefinition(
                    id=c["id"],
                    name=c["name"],
                    steps=[ChainStep(pattern=p) for p in c["steps"]],
                    window_seconds=c.get("window_seconds", 300),
                    severity=c.get("severity", "critical"),
                    description=c.get("description", ""),
                )
            )
        self.state_path = state_path
        # State: chain_id -> list of {step_index, timestamp, matched_text}
        self._state: dict[str, list[dict]] = {}
        if state_path and state_path.exists():
            try:
                self._load_state()
            except Exception:
                self._state = {}

    def _load_state(self) -> None:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                data = {}
            # Validate each value is a list
            self._state = {k: v for k, v in data.items() if isinstance(v, list)}
        except (json.JSONDecodeError, OSError):
            self._state = {}

    def _save_state(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.state_path.with_suffix(f".tmp.{os.getpid()}")
            tmp_path.write_text(json.dumps(self._state), encoding="utf-8")
            tmp_path.replace(self.state_path)  # Atomic rename
        except OSError:
            # Clean up temp file on failure
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def check(self, text: str) -> list[ChainMatch]:
        """Check text against all chain definitions. Returns completed chains."""
        now = time.time()
        completed: list[ChainMatch] = []

        for chain in self.chains:
            chain_state = self._state.get(chain.id, [])

            # Expire old entries outside the window
            chain_state = [
                s for s in chain_state
                if now - s["timestamp"] < chain.window_seconds
            ]

            # Determine which step we're expecting next
            next_step_idx = len(chain_state)
            if next_step_idx >= len(chain.steps):
                # Chain already completed, reset
                chain_state = []
                next_step_idx = 0

            step = chain.steps[next_step_idx]
            if step.compiled.search(text):
                chain_state.append({
                    "step_index": next_step_idx,
                    "timestamp": now,
                    "matched_text": text[:200],
                })

                # Check if chain is complete
                if len(chain_state) == len(chain.steps):
                    completed.append(
                        ChainMatch(
                            chain_id=chain.id,
                            chain_name=chain.name,
                            completed_steps=[s["matched_text"] for s in chain_state],
                            severity=chain.severity,
                        )
                    )
                    chain_state = []  # Reset after completion

            self._state[chain.id] = chain_state

        self._save_state()
        return completed

    def reset(self) -> None:
        """Reset all chain state."""
        self._state = {}
        if self.state_path and self.state_path.exists():
            self.state_path.unlink()
