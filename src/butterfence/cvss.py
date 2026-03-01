"""CVSS v3.1 base score calculation for ButterFence threat categories."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# CVSS v3.1 metric enums with float weights
# See: https://www.first.org/cvss/v3.1/specification-document
# ---------------------------------------------------------------------------

class AttackVector(float, Enum):
    NETWORK = 0.85
    ADJACENT = 0.62
    LOCAL = 0.55
    PHYSICAL = 0.20


class AttackComplexity(float, Enum):
    LOW = 0.77
    HIGH = 0.44


class PrivilegesRequired(float, Enum):
    NONE = 0.85
    LOW = 0.62       # scope unchanged
    HIGH = 0.27      # scope unchanged
    LOW_CHANGED = 0.68   # scope changed
    HIGH_CHANGED = 0.50  # scope changed


class UserInteraction(float, Enum):
    NONE = 0.85
    REQUIRED = 0.62


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class ImpactMetric(float, Enum):
    HIGH = 0.56
    LOW = 0.22
    NONE = 0.0


# ---------------------------------------------------------------------------
# CVSS vector dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CVSSVector:
    """Represents a CVSS v3.1 base vector."""
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: ImpactMetric
    integrity: ImpactMetric
    availability: ImpactMetric

    @property
    def vector_string(self) -> str:
        av_map = {0.85: "N", 0.62: "A", 0.55: "L", 0.20: "P"}
        ac_map = {0.77: "L", 0.44: "H"}
        pr_map = {0.85: "N", 0.62: "L", 0.68: "L", 0.27: "H", 0.50: "H"}
        ui_map = {0.85: "N", 0.62: "R"}
        cia_map = {0.56: "H", 0.22: "L", 0.0: "N"}

        parts = [
            "CVSS:3.1",
            f"AV:{av_map.get(self.attack_vector.value, 'N')}",
            f"AC:{ac_map.get(self.attack_complexity.value, 'L')}",
            f"PR:{pr_map.get(self.privileges_required.value, 'N')}",
            f"UI:{ui_map.get(self.user_interaction.value, 'N')}",
            f"S:{self.scope.value}",
            f"C:{cia_map.get(self.confidentiality.value, 'N')}",
            f"I:{cia_map.get(self.integrity.value, 'N')}",
            f"A:{cia_map.get(self.availability.value, 'N')}",
        ]
        return "/".join(parts)


@dataclass
class CVSSResult:
    """Result of a CVSS v3.1 base score calculation."""
    score: float
    severity_label: str
    vector: CVSSVector
    vector_string: str


# ---------------------------------------------------------------------------
# CVSS v3.1 base score calculation (spec-compliant)
# ---------------------------------------------------------------------------

def _roundup(value: float) -> float:
    """CVSS spec roundup: round to 1 decimal, always ceiling."""
    return math.ceil(value * 10) / 10


def calculate_cvss_base_score(vector: CVSSVector) -> CVSSResult:
    """Calculate CVSS v3.1 base score from a vector.

    Implements the formula from the official CVSS v3.1 specification.
    """
    c = vector.confidentiality.value
    i = vector.integrity.value
    a = vector.availability.value

    # Impact Sub Score (ISS)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Impact
    if vector.scope == Scope.UNCHANGED:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # If impact <= 0, base score is 0
    if impact <= 0:
        return CVSSResult(
            score=0.0,
            severity_label="None",
            vector=vector,
            vector_string=vector.vector_string,
        )

    # Exploitability
    exploitability = (
        8.22
        * vector.attack_vector.value
        * vector.attack_complexity.value
        * vector.privileges_required.value
        * vector.user_interaction.value
    )

    # Base Score
    if vector.scope == Scope.UNCHANGED:
        base_score = _roundup(min(impact + exploitability, 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    severity_label = _score_to_severity(base_score)

    return CVSSResult(
        score=base_score,
        severity_label=severity_label,
        vector=vector,
        vector_string=vector.vector_string,
    )


def _score_to_severity(score: float) -> str:
    """Map CVSS score to severity label per spec."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


# ---------------------------------------------------------------------------
# Category-to-CVSS mapping: maps each ButterFence threat category to a
# realistic CVSS v3.1 vector.
# ---------------------------------------------------------------------------

CATEGORY_CVSS_VECTORS: dict[str, CVSSVector] = {
    "destructive_shell": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.NONE,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.HIGH,
    ),
    "secret_access": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.NONE,
        availability=ImpactMetric.NONE,
    ),
    "secret_exfil": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.LOW,
        availability=ImpactMetric.NONE,
    ),
    "risky_git": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.NONE,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.LOW,
    ),
    "network_exfil": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.NONE,
        availability=ImpactMetric.NONE,
    ),
    "python_dangerous": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.LOW,
    ),
    "sql_injection": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.NONE,
    ),
    "docker_escape": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.HIGH,
    ),
    "cloud_credentials": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.LOW,
        availability=ImpactMetric.NONE,
    ),
    "supply_chain": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.NONE,
    ),
    "privilege_escalation": CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=ImpactMetric.HIGH,
        integrity=ImpactMetric.HIGH,
        availability=ImpactMetric.HIGH,
    ),
}


def get_cvss_for_category(category: str) -> CVSSResult:
    """Get the CVSS v3.1 score for a ButterFence threat category.

    Falls back to a medium-severity default if category is unknown.
    """
    default_vector = CVSSVector(
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=ImpactMetric.LOW,
        integrity=ImpactMetric.LOW,
        availability=ImpactMetric.NONE,
    )
    vector = CATEGORY_CVSS_VECTORS.get(category, default_vector)
    return calculate_cvss_base_score(vector)
