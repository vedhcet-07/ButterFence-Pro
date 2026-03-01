"""SQLite database layer for ButterFence.

Provides connection management, schema migration, CRUD operations for
all 6 tables, and a tamper-evident audit log with SHA-256 chain checksums.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Default DB path relative to project root
DB_FILENAME = "butterfence.db"


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def get_db_path(project_dir: Path) -> Path:
    """Return the path to the SQLite database file."""
    return project_dir / ".butterfence" / DB_FILENAME


def _get_schema_sql() -> str:
    """Load the schema SQL from the assets directory."""
    # Try relative to this file's package location
    pkg_dir = Path(__file__).parent.parent.parent
    schema_path = pkg_dir / "assets" / "schema.sql"
    if schema_path.exists():
        return schema_path.read_text(encoding="utf-8")

    # Fallback: inline minimal schema
    return _INLINE_SCHEMA


# Inline fallback schema (same as assets/schema.sql but embedded)
_INLINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    hook_event TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_input TEXT NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL CHECK(decision IN ('block', 'warn', 'allow')),
    reason TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    match_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'block',
    severity TEXT NOT NULL DEFAULT 'high',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,
    pattern_type TEXT NOT NULL DEFAULT 'glob',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    total_scenarios INTEGER NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    score REAL NOT NULL DEFAULT 0.0,
    grade TEXT NOT NULL DEFAULT '',
    model_used TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    category TEXT NOT NULL,
    patterns_added TEXT NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL DEFAULT '',
    source_scan_id INTEGER REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event_type TEXT NOT NULL,
    event_data TEXT NOT NULL DEFAULT '{}',
    previous_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
"""


def init_db(project_dir: Path) -> sqlite3.Connection:
    """Initialize the database, creating it if needed, and apply schema.

    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = get_db_path(project_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Apply schema (idempotent with IF NOT EXISTS)
    schema_sql = _get_schema_sql()
    conn.executescript(schema_sql)

    logger.debug("Database initialized at %s", db_path)
    return conn


@contextmanager
def get_connection(project_dir: Path):
    """Context manager for database connections."""
    conn = init_db(project_dir)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Threats CRUD
# ---------------------------------------------------------------------------

def insert_threat(
    conn: sqlite3.Connection,
    *,
    hook_event: str,
    tool_name: str,
    tool_input: dict,
    decision: str,
    reason: str = "",
    category: str = "",
    severity: str = "",
    match_count: int = 0,
) -> int:
    """Insert a threat interception record. Returns the new row ID."""
    cur = conn.execute(
        """INSERT INTO threats
           (hook_event, tool_name, tool_input, decision, reason, category, severity, match_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (hook_event, tool_name, json.dumps(tool_input), decision, reason,
         category, severity, match_count),
    )
    conn.commit()

    # Also write to audit log
    _append_audit_log(conn, "threat_detected", {
        "threat_id": cur.lastrowid,
        "tool_name": tool_name,
        "decision": decision,
        "category": category,
    })

    return cur.lastrowid


def get_threats(
    conn: sqlite3.Connection,
    *,
    decision: str | None = None,
    category: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query threats with optional filters."""
    query = "SELECT * FROM threats WHERE 1=1"
    params: list = []

    if decision:
        query += " AND decision = ?"
        params.append(decision)
    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def count_threats(conn: sqlite3.Connection, decision: str | None = None) -> int:
    """Count threats, optionally filtered by decision."""
    if decision:
        row = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE decision = ?", (decision,)
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# Rules CRUD
# ---------------------------------------------------------------------------

def insert_rule(
    conn: sqlite3.Connection,
    *,
    category: str,
    pattern: str,
    action: str = "block",
    severity: str = "high",
) -> int:
    """Insert a detection rule. Returns the new row ID."""
    cur = conn.execute(
        """INSERT INTO rules (category, pattern, action, severity)
           VALUES (?, ?, ?, ?)""",
        (category, pattern, action, severity),
    )
    conn.commit()
    return cur.lastrowid


def get_rules(conn: sqlite3.Connection, category: str | None = None) -> list[dict]:
    """Get all rules, optionally filtered by category."""
    if category:
        rows = conn.execute(
            "SELECT * FROM rules WHERE category = ? ORDER BY id", (category,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM rules ORDER BY id").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Whitelist CRUD
# ---------------------------------------------------------------------------

def insert_whitelist(
    conn: sqlite3.Connection,
    *,
    pattern: str,
    pattern_type: str = "glob",
    reason: str = "",
) -> int:
    """Insert a whitelist entry. Returns the new row ID."""
    cur = conn.execute(
        """INSERT OR IGNORE INTO whitelist (pattern, pattern_type, reason)
           VALUES (?, ?, ?)""",
        (pattern, pattern_type, reason),
    )
    conn.commit()
    return cur.lastrowid


def get_whitelist(conn: sqlite3.Connection) -> list[dict]:
    """Get all whitelist entries."""
    rows = conn.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scans CRUD
# ---------------------------------------------------------------------------

def insert_scan(
    conn: sqlite3.Connection,
    *,
    scan_type: str,
    total_scenarios: int = 0,
    passed: int = 0,
    failed: int = 0,
    score: float = 0.0,
    grade: str = "",
    model_used: str = "",
    details: dict | None = None,
) -> int:
    """Insert a scan result. Returns the new row ID."""
    cur = conn.execute(
        """INSERT INTO scans
           (scan_type, total_scenarios, passed, failed, score, grade, model_used, details_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_type, total_scenarios, passed, failed, score, grade,
         model_used, json.dumps(details or {})),
    )
    conn.commit()

    _append_audit_log(conn, "scan_completed", {
        "scan_id": cur.lastrowid,
        "scan_type": scan_type,
        "score": score,
        "grade": grade,
    })

    return cur.lastrowid


def get_scans(
    conn: sqlite3.Connection,
    scan_type: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Get scan results, optionally filtered by type."""
    if scan_type:
        rows = conn.execute(
            "SELECT * FROM scans WHERE scan_type = ? ORDER BY timestamp DESC LIMIT ?",
            (scan_type, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Patches CRUD
# ---------------------------------------------------------------------------

def insert_patch(
    conn: sqlite3.Connection,
    *,
    category: str,
    patterns_added: list[str],
    explanation: str = "",
    source_scan_id: int | None = None,
) -> int:
    """Insert a patch record. Returns the new row ID."""
    cur = conn.execute(
        """INSERT INTO patches (category, patterns_added, explanation, source_scan_id)
           VALUES (?, ?, ?, ?)""",
        (category, json.dumps(patterns_added), explanation, source_scan_id),
    )
    conn.commit()
    return cur.lastrowid


def get_patches(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    """Get recent patches."""
    rows = conn.execute(
        "SELECT * FROM patches ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Audit Log — tamper-evident with SHA-256 chain
# ---------------------------------------------------------------------------

def _compute_hash(entry_data: str, previous_hash: str) -> str:
    """Compute SHA-256 hash of entry data chained with previous hash."""
    payload = f"{previous_hash}:{entry_data}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_last_hash(conn: sqlite3.Connection) -> str:
    """Get the hash of the most recent audit log entry."""
    row = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else "genesis"


def _append_audit_log(
    conn: sqlite3.Connection,
    event_type: str,
    event_data: dict,
) -> int:
    """Append an entry to the tamper-evident audit log.

    Each entry's hash is computed from its data + the previous entry's hash,
    forming an integrity chain similar to a blockchain.
    """
    data_str = json.dumps(event_data, sort_keys=True)
    previous_hash = _get_last_hash(conn)
    entry_hash = _compute_hash(data_str, previous_hash)

    cur = conn.execute(
        """INSERT INTO audit_log (event_type, event_data, previous_hash, entry_hash)
           VALUES (?, ?, ?, ?)""",
        (event_type, data_str, previous_hash, entry_hash),
    )
    conn.commit()
    return cur.lastrowid


def get_audit_log(
    conn: sqlite3.Connection,
    event_type: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Get audit log entries."""
    if event_type:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT ?",
            (event_type, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def verify_audit_log(conn: sqlite3.Connection) -> tuple[bool, int, str]:
    """Verify the integrity of the entire audit log chain.

    Returns (is_valid, entries_checked, error_message).
    """
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id ASC"
    ).fetchall()

    if not rows:
        return True, 0, ""

    prev_hash = "genesis"
    for i, row in enumerate(rows):
        row_dict = dict(row)
        expected_hash = _compute_hash(row_dict["event_data"], prev_hash)

        if row_dict["previous_hash"] != prev_hash:
            return False, i, (
                f"Entry {row_dict['id']}: previous_hash mismatch "
                f"(expected {prev_hash[:16]}..., got {row_dict['previous_hash'][:16]}...)"
            )

        if row_dict["entry_hash"] != expected_hash:
            return False, i, (
                f"Entry {row_dict['id']}: entry_hash mismatch "
                f"(expected {expected_hash[:16]}..., got {row_dict['entry_hash'][:16]}...)"
            )

        prev_hash = row_dict["entry_hash"]

    return True, len(rows), ""


# ---------------------------------------------------------------------------
# Migration from JSONL
# ---------------------------------------------------------------------------

def migrate_from_jsonl(project_dir: Path) -> int:
    """Import existing events.jsonl records into the threats table.

    Returns the number of records imported.
    """
    jsonl_path = project_dir / ".butterfence" / "logs" / "events.jsonl"
    if not jsonl_path.exists():
        return 0

    imported = 0
    with get_connection(project_dir) as conn:
        try:
            lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return 0

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract category from reason string
            category = ""
            reason = ev.get("reason", "")
            if ":" in reason and "[" in reason:
                try:
                    category = reason.split(":")[1].split("]")[0]
                except (IndexError, ValueError):
                    pass

            conn.execute(
                """INSERT INTO threats
                   (timestamp, hook_event, tool_name, tool_input, decision,
                    reason, category, match_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev.get("timestamp", ""),
                    ev.get("hook_event", ""),
                    ev.get("tool_name", ""),
                    json.dumps({"summary": ev.get("tool_input_summary", "")}),
                    ev.get("decision", "allow"),
                    reason,
                    category,
                    ev.get("match_count", 0),
                ),
            )
            imported += 1

        conn.commit()

    logger.info("Migrated %d events from JSONL to SQLite.", imported)
    return imported
