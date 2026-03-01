"""Core matching engine - pure function, no side effects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from butterfence.cache import get_compiled_rules
from butterfence.entropy import find_high_entropy_strings
from butterfence.normalizer import normalize_command, split_commands
from butterfence.obfuscation import detect_obfuscation
from butterfence.rules import Action, CompiledRule, RuleMatch
from butterfence.utils import normalize_path

# ReDoS protection: truncate text longer than 100KB before regex matching
MAX_TEXT_LENGTH = 100_000

# File extensions where entropy findings are WARN not BLOCK
_ENTROPY_WARN_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".markdown", ".rst", ".txt",        # docs
    ".yaml", ".yml", ".toml", ".json", ".xml",  # config
    ".html", ".htm", ".css",                     # web
    ".svg", ".csv",                              # data
})

# Regex to detect output redirection targets in Bash commands
_REDIRECT_PATTERN = re.compile(
    r'(?:>>|>|tee\s+(?:-a\s+)?|cp\s+\S+\s+)\s*(\S+)',
    re.IGNORECASE,
)


@dataclass
class HookPayload:
    hook_event: str  # "PreToolUse" / "PostToolUse"
    tool_name: str   # "Bash", "Read", "Write", "Edit"
    tool_input: dict  # {"command": "..."} or {"file_path": "..."}


@dataclass
class MatchResult:
    decision: str  # "block", "warn", "allow"
    matches: list[RuleMatch] = field(default_factory=list)
    reason: str = ""


def _extract_matchable_text(payload: HookPayload) -> list[str]:
    """Extract text strings to match against from a hook payload."""
    texts: list[str] = []
    tool = payload.tool_name

    if tool == "Bash":
        cmd = payload.tool_input.get("command", "")
        if cmd:
            # Split compound commands and normalize each
            parts = split_commands(cmd)
            for part in parts:
                texts.append(normalize_command(part))
            # Also include the full original for pattern coverage
            texts.append(cmd)

    elif tool == "Read":
        fp = payload.tool_input.get("file_path", "")
        if fp:
            texts.append(normalize_path(fp))

    elif tool in ("Write", "Edit"):
        fp = payload.tool_input.get("file_path", "")
        if fp:
            texts.append(normalize_path(fp))
        content = payload.tool_input.get("content", "")
        if content:
            texts.append(content)
        new_string = payload.tool_input.get("new_string", "")
        if new_string:
            texts.append(new_string)

    return texts


def _get_obfuscation_texts(texts: list[str]) -> list[str]:
    """Extract decoded text from obfuscation findings."""
    extra: list[str] = []
    for text in texts:
        findings = detect_obfuscation(text)
        for f in findings:
            if f.decoded_text and f.decoded_text != "<decode-failed>":
                extra.append(f.decoded_text)
    return extra


def _get_entropy_matches(texts: list[str], threshold: float) -> list[RuleMatch]:
    """Check for high-entropy strings that may be secrets."""
    matches: list[RuleMatch] = []
    for text in texts:
        findings = find_high_entropy_strings(text, threshold=threshold)
        for f in findings:
            matches.append(
                RuleMatch(
                    category="secret_exfil",
                    severity="high",
                    action="block",
                    pattern=f"entropy={f.entropy}",
                    matched_text=f.text[:200],
                )
            )
    return matches


def _is_safe_listed(text: str, rule: CompiledRule) -> bool:
    """Check if the text matches any safe-list pattern for this rule."""
    return any(sp.search(text) for sp in rule.safe_patterns)


def _is_entropy_warn_file(payload: HookPayload) -> bool:
    """Check if this file type should get WARN instead of BLOCK for entropy.

    Doc/config/data file extensions get a downgraded action because
    high-entropy tokens in Markdown, YAML, JSON, etc. are commonly
    legitimate (e.g. UUIDs, hashes, base64 examples).
    """
    from pathlib import Path

    file_path = payload.tool_input.get("file_path", "")
    if not file_path:
        return False
    ext = Path(file_path).suffix.lower()
    return ext in _ENTROPY_WARN_EXTENSIONS


def _check_bash_redirect_to_secret(
    command: str,
    config: dict,
) -> list[RuleMatch]:
    """Check if a Bash command redirects output to a secret file path.

    Detects patterns like:
          - cat > .env << 'EOF'
          - echo content > id_rsa
          - tee ~/.aws/credentials
          - printf key >> .env.production
          - cp something .env
    """
    matches: list[RuleMatch] = []

    # Find all redirect targets in the command
    targets = _REDIRECT_PATTERN.findall(command)
    if not targets:
        return matches

    # Get secret file patterns from config
    secret_config = config.get("categories", {}).get("secret_access", {})
    if not secret_config.get("enabled", True):
        return matches

    raw_patterns = secret_config.get("patterns", [])
    compiled_patterns: list[re.Pattern[str]] = []
    for pat in raw_patterns:
        try:
            compiled_patterns.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            continue

    # Get safe_list patterns to respect user customization
    safe_raw = secret_config.get("safe_list", [])
    compiled_safe: list[re.Pattern[str]] = []
    for sp in safe_raw:
        try:
            compiled_safe.append(re.compile(sp, re.IGNORECASE))
        except re.error:
            continue

    # Check each redirect target against secret patterns
    for target in targets:
        # Strip quotes from target
        target_clean = target.strip("'\"")
        target_norm = normalize_path(target_clean)

        # Skip if safe-listed
        if any(sp.search(target_norm) for sp in compiled_safe):
            continue

        for pat in compiled_patterns:
            if pat.search(target_norm):
                matches.append(RuleMatch(
                    category="secret_access",
                    severity="critical",
                    action="block",
                    pattern=f"bash_redirect_to_secret:{pat.pattern}",
                    matched_text=f"redirect to {target_clean}",
                ))
                break  # One match per target is enough

    return matches


def match_rules(
    payload: HookPayload,
    config: dict,
    project_dir: str | None = None,
    edge_mode: bool = False,
) -> MatchResult:
    """Match a hook payload against compiled rules. Pure function.

    Returns MatchResult with the highest-severity decision.
    Checks whitelist before running rule matching.

    Args:
        payload: The hook event to evaluate.
        config: Loaded ButterFence config dict.
        project_dir: Project root directory.
        edge_mode: If True, use ONNX/heuristic classifier instead of
                   regex rules. Zero cloud calls. Falls through to regex
                   if edge prediction is low-confidence.
    """
    # --- Whitelist check ---
    from butterfence.whitelist import is_file_whitelisted, load_whitelist
    from pathlib import Path

    wl_dir = Path(project_dir) if project_dir else None
    whitelist = load_whitelist(wl_dir)

    # If the target file is whitelisted, allow immediately
    file_path = payload.tool_input.get("file_path", "")
    if file_path and is_file_whitelisted(file_path, whitelist):
        return MatchResult(decision="allow")

    # --- Edge mode: ONNX / heuristic classification ---
    if edge_mode:
        from butterfence.edge.onnx_classifier import get_classifier

        texts = _extract_matchable_text(payload)
        if not texts:
            return MatchResult(decision="allow")

        classifier = get_classifier()
        # Classify the combined text
        combined = " ".join(texts)
        prediction = classifier.predict(combined)

        if prediction.category != "benign":
            from butterfence.rules import RuleMatch as _RM
            edge_match = _RM(
                category=prediction.category,
                severity=prediction.severity,
                action="block",
                pattern=f"edge:{prediction.category}:{prediction.confidence:.2f}",
                matched_text=combined[:200],
            )
            return MatchResult(
                decision="block",
                matches=[edge_match],
                reason=(
                    f"[edge:{prediction.severity}:{prediction.category}] "
                    f"confidence={prediction.confidence:.2f} "
                    f"provider={prediction.provider} "
                    f"latency={prediction.inference_ms:.1f}ms"
                ),
            )
        # Benign prediction — fall through to regex for extra safety

    rules = get_compiled_rules(config)
    texts = _extract_matchable_text(payload)

    if not texts:
        return MatchResult(decision="allow")

    # ReDoS protection: truncate oversized text before regex matching
    texts = [t[:MAX_TEXT_LENGTH] if len(t) > MAX_TEXT_LENGTH else t for t in texts]

    # Add decoded obfuscation text for matching
    obf_texts = _get_obfuscation_texts(texts)
    all_texts = texts + obf_texts

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique_texts: list[str] = []
    for t in all_texts:
        if t not in seen:
            seen.add(t)
            unique_texts.append(t)

    all_matches: list[RuleMatch] = []
    highest_action = Action.ALLOW

    for rule in rules:
        for text in unique_texts:
            if rule.pattern.search(text) and not _is_safe_listed(text, rule):
                match = RuleMatch(
                    category=rule.category,
                    severity=rule.severity.value,
                    action=rule.action.value,
                    pattern=rule.raw_pattern,
                    matched_text=text[:200],
                )
                all_matches.append(match)
                if _action_priority(rule.action) > _action_priority(highest_action):
                    highest_action = rule.action

    # Check for Bash redirects to secret files
    if payload.tool_name == "Bash":
        cmd = payload.tool_input.get("command", "")
        if cmd:
            redirect_matches = _check_bash_redirect_to_secret(cmd, config)
            for rm in redirect_matches:
                all_matches.append(rm)
                if _action_priority(Action.BLOCK) > _action_priority(highest_action):
                    highest_action = Action.BLOCK

    # Check entropy for Write/Edit content
    if payload.tool_name in ("Write", "Edit"):
        try:
            threshold = float(config.get("entropy_threshold", 4.5))
        except (TypeError, ValueError):
            threshold = 4.5
        entropy_matches = _get_entropy_matches(texts, threshold)

        # For doc/config files, downgrade entropy findings to WARN
        entropy_action = Action.WARN if _is_entropy_warn_file(payload) else Action.BLOCK

        for em in entropy_matches:
            em.action = entropy_action.value  # "warn" or "block"
            all_matches.append(em)
            if _action_priority(entropy_action) > _action_priority(highest_action):
                highest_action = entropy_action

    if not all_matches:
        return MatchResult(decision="allow")

    reasons = []
    for m in all_matches:
        reasons.append(f"[{m.severity}:{m.category}] matched pattern: {m.pattern}")

    return MatchResult(
        decision=highest_action.value,
        matches=all_matches,
        reason="; ".join(reasons),
    )


def _action_priority(action: Action) -> int:
    """Higher number = more restrictive action."""
    return {Action.ALLOW: 0, Action.WARN: 1, Action.BLOCK: 2}[action]

