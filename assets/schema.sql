-- ButterFence SQLite schema — 6 tables
-- Version: 1.0

-- Threat interception records
CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    hook_event  TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    tool_input  TEXT    NOT NULL DEFAULT '{}',
    decision    TEXT    NOT NULL CHECK(decision IN ('block', 'warn', 'allow')),
    reason      TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT '' CHECK(severity IN ('', 'critical', 'high', 'medium', 'low')),
    match_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_decision  ON threats(decision);
CREATE INDEX IF NOT EXISTS idx_threats_category  ON threats(category);

-- Detection rules (snapshot of active rules)
CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT    NOT NULL,
    pattern     TEXT    NOT NULL,
    action      TEXT    NOT NULL DEFAULT 'block',
    severity    TEXT    NOT NULL DEFAULT 'high',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);

-- Whitelist entries
CREATE TABLE IF NOT EXISTS whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT    NOT NULL UNIQUE,
    pattern_type TEXT   NOT NULL DEFAULT 'glob' CHECK(pattern_type IN ('glob', 'regex', 'exact')),
    reason      TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Scan results
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT    NOT NULL CHECK(scan_type IN ('audit', 'redteam', 'supply_chain', 'secret')),
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    total_scenarios  INTEGER NOT NULL DEFAULT 0,
    passed          INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    score           REAL    NOT NULL DEFAULT 0.0,
    grade           TEXT    NOT NULL DEFAULT '',
    model_used      TEXT    NOT NULL DEFAULT '',
    details_json    TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scans_type      ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);

-- Auto-generated rule patches
CREATE TABLE IF NOT EXISTS patches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    category        TEXT    NOT NULL,
    patterns_added  TEXT    NOT NULL DEFAULT '[]',
    explanation     TEXT    NOT NULL DEFAULT '',
    source_scan_id  INTEGER REFERENCES scans(id)
);

-- Tamper-evident audit log with SHA-256 chain
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event_type      TEXT    NOT NULL,
    event_data      TEXT    NOT NULL DEFAULT '{}',
    previous_hash   TEXT    NOT NULL DEFAULT '',
    entry_hash      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_type ON audit_log(event_type);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);
