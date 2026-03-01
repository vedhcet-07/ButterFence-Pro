"""Event log analytics — `butterfence analytics`."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

VALID_PERIODS = {"1h", "24h", "7d", "30d", "all"}


@dataclass
class AnalyticsResult:
    total_events: int = 0
    blocks: int = 0
    warns: int = 0
    allows: int = 0
    by_tool: Counter = field(default_factory=Counter)
    by_category: Counter = field(default_factory=Counter)
    blocked_patterns: Counter = field(default_factory=Counter)
    events_over_time: list[tuple[str, int]] = field(default_factory=list)
    threat_trend: str = "stable"

    @property
    def block_rate(self) -> float:
        return (self.blocks / self.total_events * 100) if self.total_events else 0.0


def _parse_period(period: str) -> float | None:
    """Parse period string to seconds. Returns None for 'all'."""
    if period == "all":
        return None
    unit_map = {"h": 3600, "d": 86400}
    try:
        num = int(period[:-1])
        unit = period[-1]
        return num * unit_map.get(unit, 3600)
    except (ValueError, IndexError):
        return None


def _analyze_from_db(project_dir: Path, period: str) -> AnalyticsResult | None:
    """Try to analyze events from SQLite database."""
    try:
        from butterfence.database import get_db_path, init_db
    except ImportError:
        return None

    db_path = get_db_path(project_dir)
    if not db_path.exists():
        return None

    try:
        conn = init_db(project_dir)
    except Exception:
        return None

    try:
        # Build time filter
        where_clause = ""
        params: list = []
        cutoff_seconds = _parse_period(period)
        if cutoff_seconds is not None:
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            cutoff_dt = now - timedelta(seconds=cutoff_seconds)
            where_clause = "WHERE timestamp >= ?"
            params.append(cutoff_dt.isoformat())

        # Total counts
        rows = conn.execute(
            f"SELECT * FROM threats {where_clause} ORDER BY timestamp ASC", params
        ).fetchall()

        if not rows:
            return AnalyticsResult()

        result = AnalyticsResult()
        result.total_events = len(rows)
        hourly_counts: Counter = Counter()
        recent_blocks: list[float] = []

        for row in rows:
            r = dict(row)
            decision = r.get("decision", "allow")
            if decision == "block":
                result.blocks += 1
            elif decision == "warn":
                result.warns += 1
            else:
                result.allows += 1

            result.by_tool[r.get("tool_name", "unknown")] += 1

            cat = r.get("category", "")
            if cat:
                result.by_category[cat] += 1

            if decision in ("block", "warn"):
                try:
                    ti = json.loads(r.get("tool_input", "{}"))
                    summary = str(ti.get("summary", str(ti)))[:50]
                except (json.JSONDecodeError, TypeError):
                    summary = ""
                result.blocked_patterns[summary] += 1

            ts_str = r.get("timestamp", "")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str)
                    hour_key = ts.strftime("%Y-%m-%d %H:00")
                    hourly_counts[hour_key] += 1
                    if decision == "block":
                        recent_blocks.append(ts.timestamp())
                except (ValueError, TypeError):
                    pass

        result.events_over_time = sorted(hourly_counts.items())

        if len(recent_blocks) >= 4:
            mid = len(recent_blocks) // 2
            first_half = mid
            second_half = len(recent_blocks) - mid
            if second_half > first_half * 1.5:
                result.threat_trend = "increasing"
            elif second_half < first_half * 0.5:
                result.threat_trend = "decreasing"

        return result
    except Exception as exc:
        logger.debug("SQLite analytics failed, falling back to JSONL: %s", exc)
        return None
    finally:
        conn.close()


def analyze_events(
    project_dir: Path,
    period: str = "all",
) -> AnalyticsResult:
    """Parse events from SQLite (preferred) or events.jsonl and compute analytics."""
    # Validate period
    if period not in VALID_PERIODS:
        logger.warning("Invalid period '%s', using 'all'. Valid: %s", period, VALID_PERIODS)
        period = "all"

    # Try SQLite first
    db_result = _analyze_from_db(project_dir, period)
    if db_result is not None:
        return db_result

    # Fallback to JSONL
    log_path = project_dir / ".butterfence" / "logs" / "events.jsonl"
    result = AnalyticsResult()

    if not log_path.exists():
        return result

    cutoff_seconds = _parse_period(period)
    now = datetime.now(timezone.utc)

    events: list[dict] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Apply time filter
            if cutoff_seconds is not None:
                ts_str = ev.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if (now - ts).total_seconds() > cutoff_seconds:
                        continue
                except (ValueError, TypeError):
                    continue

            events.append(ev)

    result.total_events = len(events)

    # Compute counters
    hourly_counts: Counter = Counter()
    recent_blocks: list[float] = []

    for ev in events:
        decision = ev.get("decision", "allow")
        if decision == "block":
            result.blocks += 1
        elif decision == "warn":
            result.warns += 1
        else:
            result.allows += 1

        result.by_tool[ev.get("tool_name", "unknown")] += 1

        # Extract category from reason
        reason = ev.get("reason", "")
        for part in reason.split(";"):
            if ":" in part and "[" in part:
                try:
                    cat = part.split(":")[1].split("]")[0]
                    result.by_category[cat] += 1
                except (IndexError, ValueError):
                    pass

        if decision in ("block", "warn"):
            summary = ev.get("tool_input_summary", "")[:50]
            result.blocked_patterns[summary] += 1

        # Time-based grouping
        ts_str = ev.get("timestamp", "")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str)
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key] += 1

                if decision == "block":
                    recent_blocks.append(ts.timestamp())
            except (ValueError, TypeError):
                pass

    # Events over time
    result.events_over_time = sorted(hourly_counts.items())

    # Trend analysis
    if len(recent_blocks) >= 4:
        mid = len(recent_blocks) // 2
        first_half = mid
        second_half = len(recent_blocks) - mid
        if second_half > first_half * 1.5:
            result.threat_trend = "increasing"
        elif second_half < first_half * 0.5:
            result.threat_trend = "decreasing"

    return result
