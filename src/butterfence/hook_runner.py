"""Claude Code hook entry point. Reads stdin JSON, outputs decision JSON to stdout."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from butterfence.config import load_config
from butterfence.log_rotation import rotate_if_needed
from butterfence.matcher import HookPayload, MatchResult, match_rules


def _find_project_root() -> Path:
    """Walk up from cwd looking for .butterfence/ directory."""
    cwd = Path.cwd()
    for d in [cwd, *cwd.parents]:
        if (d / ".butterfence").is_dir():
            return d
    return cwd


def _log_event(project_root: Path, payload: HookPayload, result: MatchResult) -> None:
    """Append event to .butterfence/logs/events.jsonl and SQLite database."""
    try:
        log_dir = project_root / ".butterfence" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "events.jsonl"

        # Rotate if needed
        rotate_if_needed(log_path)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hook_event": payload.hook_event,
            "tool_name": payload.tool_name,
            "tool_input_summary": _summarize_input(payload.tool_input),
            "decision": result.decision,
            "reason": result.reason,
            "match_count": len(result.matches),
        }

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass  # Best-effort logging, never crash the hook

    # Also log to SQLite (best-effort)
    try:
        from butterfence.database import insert_threat, init_db

        # Extract category from result matches
        category = ""
        severity = ""
        if result.matches:
            category = result.matches[0].category
            severity = result.matches[0].severity

        conn = init_db(project_root)
        try:
            insert_threat(
                conn,
                hook_event=payload.hook_event,
                tool_name=payload.tool_name,
                tool_input=payload.tool_input,
                decision=result.decision,
                reason=result.reason,
                category=category,
                severity=severity,
                match_count=len(result.matches),
            )
        finally:
            conn.close()
    except Exception:
        pass  # SQLite logging is best-effort


def _summarize_input(tool_input: dict) -> str:
    """Create a short summary of tool input for logging."""
    if "command" in tool_input:
        cmd = tool_input["command"]
        return cmd[:200] if len(cmd) > 200 else cmd
    if "file_path" in tool_input:
        return tool_input["file_path"]
    return str(tool_input)[:200]


def _make_hook_output(hook_event: str, result: MatchResult) -> dict | None:
    """Create Claude Code hook output JSON."""
    if result.decision == "block":
        return {
            "hookSpecificOutput": {
                "hookEventName": hook_event,
                "permissionDecision": "deny",
                "permissionDecisionReason": f"[ButterFence] BLOCKED: {result.reason}",
            }
        }
    elif result.decision == "warn":
        return {
            "hookSpecificOutput": {
                "hookEventName": hook_event,
                "permissionDecision": "ask",
                "permissionDecisionReason": f"[ButterFence WARNING] {result.reason}",
            }
        }
    # allow: no output, exit 0
    return None


def run_hook(mode: str) -> None:
    """Main hook entry point. Mode is 'pretool' or 'posttool'."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        sys.exit(1)

    # Check bypass env var
    if os.environ.get("BUTTERFENCE_BYPASS") == "1":
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    hook_event = "PreToolUse" if mode == "pretool" else "PostToolUse"

    payload = HookPayload(
        hook_event=hook_event,
        tool_name=tool_name,
        tool_input=tool_input,
    )

    project_root = _find_project_root()
    config = load_config(project_root)
    result = match_rules(payload, config)

    # Log all events (best-effort, never crash the hook)
    try:
        _log_event(project_root, payload, result)
    except Exception:
        print("[ButterFence] Warning: failed to write event log", file=sys.stderr)

    # Chain detection (post-match, for behavioral tracking)
    try:
        from butterfence.chain_detector import ChainDetector
        state_path = project_root / ".butterfence" / "chain_state.json"
        chains_config = config.get("behavioral_chains", [])
        detector = ChainDetector(
            chains=chains_config if chains_config else None,
            state_path=state_path,
        )
        # Extract text for chain checking
        texts = []
        if "command" in tool_input:
            texts.append(tool_input["command"])
        if "file_path" in tool_input:
            texts.append(tool_input["file_path"])
        for t in texts:
            chain_matches = detector.check(t)
            if chain_matches and result.decision == "allow":
                # Upgrade to block if a chain completed
                from butterfence.rules import RuleMatch
                for cm in chain_matches:
                    result.matches.append(
                        RuleMatch(
                            category="behavioral_chain",
                            severity=cm.severity,
                            action="block",
                            pattern=f"chain:{cm.chain_id}",
                            matched_text="; ".join(cm.completed_steps),
                        )
                    )
                result.decision = "block"
                result.reason = f"Behavioral chain detected: {chain_matches[0].chain_name}"
    except Exception:
        pass  # Chain detection is best-effort

    if mode == "pretool":
        output = _make_hook_output(hook_event, result)
        if output:
            try:
                json.dump(output, sys.stdout)
            except (TypeError, ValueError):
                # Fallback: output a safe block decision
                sys.stdout.write('{"hookSpecificOutput":{"decision":"block","reason":"[ButterFence] Internal error"}}')
            sys.exit(0)
    # PostToolUse: log only, no blocking
    sys.exit(0)


def main() -> None:
    """CLI entry for `python -m butterfence.hook_runner <pretool|posttool>`."""
    if len(sys.argv) < 2 or sys.argv[1] not in ("pretool", "posttool"):
        print("Usage: python -m butterfence.hook_runner <pretool|posttool>", file=sys.stderr)
        sys.exit(1)
    run_hook(sys.argv[1])


if __name__ == "__main__":
    main()
