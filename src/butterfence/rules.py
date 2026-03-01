"""Rule definitions, enums, and regex compilation."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Action(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


class Category(str, Enum):
    DESTRUCTIVE_SHELL = "destructive_shell"
    SECRET_ACCESS = "secret_access"
    SECRET_EXFIL = "secret_exfil"
    RISKY_GIT = "risky_git"
    NETWORK_EXFIL = "network_exfil"
    PYTHON_DANGEROUS = "python_dangerous"
    SQL_INJECTION = "sql_injection"
    DOCKER_ESCAPE = "docker_escape"
    CLOUD_CREDENTIALS = "cloud_credentials"
    SUPPLY_CHAIN = "supply_chain"
    PRIVILEGE_ESCALATION = "privilege_escalation"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
}


@dataclass
class CompiledRule:
    category: str
    severity: Severity
    action: Action
    pattern: re.Pattern[str]
    raw_pattern: str
    safe_patterns: list[re.Pattern[str]] = field(default_factory=list)


@dataclass
class RuleMatch:
    category: str
    severity: str
    action: str
    pattern: str
    matched_text: str


def compile_rules(config: dict) -> list[CompiledRule]:
    """Compile all enabled category patterns into CompiledRule objects."""
    rules: list[CompiledRule] = []
    categories = config.get("categories", {})
    for cat_name, cat_config in categories.items():
        if not cat_config.get("enabled", True):
            continue
        severity = Severity(cat_config.get("severity", "high"))
        action = Action(cat_config.get("action", "block"))
        safe_compiled = []
        for sp in cat_config.get("safe_list", []):
            try:
                safe_compiled.append(re.compile(sp, re.IGNORECASE))
            except re.error as exc:
                logger.warning(
                    "Skipping invalid safe_list regex in category '%s': %s (error: %s)",
                    cat_name, sp, exc
                )
                continue
        for pattern_str in cat_config.get("patterns", []):
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
            except re.error as exc:
                logger.warning(
                    "Skipping invalid regex in category '%s': %s (error: %s)",
                    cat_name, pattern_str, exc
                )
                continue
            rules.append(
                CompiledRule(
                    category=cat_name,
                    severity=severity,
                    action=action,
                    pattern=compiled,
                    raw_pattern=pattern_str,
                    safe_patterns=safe_compiled,
                )
            )
    return rules
