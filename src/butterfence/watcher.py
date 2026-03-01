"""Real-time Rich Live terminal dashboard — `butterfence watch`."""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WatchStats:
    blocks: int = 0
    warns: int = 0
    allows: int = 0
    events: list[dict] = field(default_factory=list)
    category_counts: Counter = field(default_factory=Counter)
    rule_counts: Counter = field(default_factory=Counter)
    start_time: float = field(default_factory=time.time)

    @property
    def total(self) -> int:
        return self.blocks + self.warns + self.allows

    @property
    def events_per_min(self) -> float:
        elapsed = max(time.time() - self.start_time, 1)
        return self.total / elapsed * 60


class EventTailer:
    """Tails events.jsonl, yielding new events via polling."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._offset = 0
        if log_path.exists():
            self._offset = log_path.stat().st_size

    def poll(self) -> list[dict]:
        """Return new events since last poll."""
        if not self.log_path.exists():
            self._offset = 0  # Reset if file disappeared (rotation)
            return []
        try:
            size = self.log_path.stat().st_size
        except OSError:
            return []
        if size < self._offset:
            # File was rotated/truncated -- reset to beginning
            self._offset = 0
        if size <= self._offset:
            return []

        events = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            f.seek(self._offset)
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            self._offset = f.tell()
        return events


class DbEventTailer:
    """Polls the SQLite threats table for new events."""

    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        self._last_id = 0
        # Get the current max ID to only show new events
        try:
            from butterfence.database import init_db
            conn = init_db(project_dir)
            try:
                row = conn.execute("SELECT MAX(id) FROM threats").fetchone()
                self._last_id = row[0] or 0
            finally:
                conn.close()
        except Exception:
            self._last_id = 0

    def poll(self) -> list[dict]:
        """Return new events since last poll."""
        try:
            from butterfence.database import init_db
            conn = init_db(self.project_dir)
            try:
                rows = conn.execute(
                    "SELECT * FROM threats WHERE id > ? ORDER BY id ASC",
                    (self._last_id,),
                ).fetchall()
                events = []
                for row in rows:
                    r = dict(row)
                    self._last_id = r["id"]
                    events.append({
                        "timestamp": r.get("timestamp", ""),
                        "hook_event": r.get("hook_event", ""),
                        "tool_name": r.get("tool_name", ""),
                        "tool_input_summary": r.get("reason", "")[:60],
                        "decision": r.get("decision", "allow"),
                        "reason": r.get("reason", ""),
                        "match_count": r.get("match_count", 0),
                    })
                return events
            finally:
                conn.close()
        except Exception:
            return []


def _check_quit() -> bool:
    """Cross-platform non-blocking keyboard check for 'q'."""
    if sys.platform == "win32":
        try:
            import msvcrt

            if msvcrt.kbhit():
                ch = msvcrt.getch()
                return ch in (b"q", b"Q")
        except ImportError:
            pass
    else:
        try:
            import select

            rlist, _, _ = select.select([sys.stdin], [], [], 0)
            if rlist:
                ch = sys.stdin.read(1)
                return ch in ("q", "Q")
        except Exception:
            pass
    return False


def run_watcher(
    project_dir: Path,
    refresh: float = 0.5,
    max_events: int = 50,
) -> None:
    """Run the live monitoring dashboard."""
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()
    log_path = project_dir / ".butterfence" / "logs" / "events.jsonl"

    # Use SQLite tailer if database exists, otherwise JSONL
    try:
        from butterfence.database import get_db_path
        db_path = get_db_path(project_dir)
        if db_path.exists():
            tailer: EventTailer | DbEventTailer = DbEventTailer(project_dir)
        else:
            tailer = EventTailer(log_path)
    except ImportError:
        tailer = EventTailer(log_path)
    stats = WatchStats()

    def build_display() -> Layout:
        layout = Layout()
        layout.split_row(
            Layout(name="left", ratio=2),
            Layout(name="right"),
        )

        # Left: Event feed
        event_table = Table(show_header=True, expand=True, show_edge=False)
        event_table.add_column("Time", width=10)
        event_table.add_column("Decision", width=8)
        event_table.add_column("Tool", width=8)
        event_table.add_column("Summary", ratio=1)

        recent = stats.events[-20:]
        for ev in reversed(recent):
            ts = ev.get("timestamp", "")
            if "T" in ts:
                ts = ts.split("T")[1][:8]
            decision = ev.get("decision", "allow")
            dec_style = {"block": "red bold", "warn": "yellow", "allow": "green"}.get(
                decision, ""
            )
            event_table.add_row(
                ts,
                f"[{dec_style}]{decision.upper()}[/{dec_style}]",
                ev.get("tool_name", ""),
                str(ev.get("tool_input_summary", ""))[:60],
            )

        layout["left"].update(
            Panel(event_table, title="Live Event Feed", border_style="blue")
        )

        # Right: Stats
        lines = []
        lines.append(f"[red]Blocks:[/red]  {stats.blocks}")
        lines.append(f"[yellow]Warns:[/yellow]   {stats.warns}")
        lines.append(f"[green]Allows:[/green]  {stats.allows}")
        lines.append(f"Events/min: {stats.events_per_min:.1f}")
        lines.append("")
        lines.append("[bold]Categories:[/bold]")
        for cat, count in stats.category_counts.most_common(6):
            bar = "\u2588" * min(count, 20)
            lines.append(f"  {cat[:14]:<14} {bar} {count}")
        lines.append("")
        lines.append("[bold]Top Rules:[/bold]")
        for rule, count in stats.rule_counts.most_common(5):
            lines.append(f"  {rule[:20]:<20} {count}")

        stats_text = Text.from_markup("\n".join(lines))
        layout["right"].update(
            Panel(stats_text, title="Statistics", border_style="cyan")
        )

        return layout

    # Calculate score
    def _score_text() -> str:
        total = stats.total
        if total == 0:
            return "Score: --/100"
        block_ratio = stats.blocks / total if total else 0
        score = max(0, int(100 - block_ratio * 100))
        grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "F"
        return f"Risk Score: {score}/100 ({grade})     Press 'q' quit"

    with Live(build_display(), console=console, refresh_per_second=int(1 / refresh)) as live:
        try:
            while True:
                new_events = tailer.poll()
                for ev in new_events:
                    stats.events.append(ev)
                    decision = ev.get("decision", "allow")
                    if decision == "block":
                        stats.blocks += 1
                    elif decision == "warn":
                        stats.warns += 1
                    else:
                        stats.allows += 1

                    # Track categories from reason
                    reason = ev.get("reason", "")
                    if ":" in reason:
                        # Extract category from [severity:category]
                        for part in reason.split(";"):
                            if ":" in part and "[" in part:
                                try:
                                    cat = part.split(":")[1].split("]")[0]
                                    stats.category_counts[cat] += 1
                                except (IndexError, ValueError):
                                    pass

                    summary = ev.get("tool_input_summary", "")[:30]
                    if decision != "allow":
                        stats.rule_counts[summary] += 1

                    # Trim old events
                    if len(stats.events) > max_events:
                        stats.events = stats.events[-max_events:]

                live.update(
                    Panel(
                        build_display(),
                        title="ButterFence Live Monitor",
                        subtitle=_score_text(),
                        border_style="bold blue",
                    )
                )

                if _check_quit():
                    break

                time.sleep(refresh)
        except KeyboardInterrupt:
            pass

    console.print("\n[bold]Watcher stopped.[/bold]")
