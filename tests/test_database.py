"""Tests for the SQLite database layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from butterfence.database import (
    count_threats,
    get_audit_log,
    get_connection,
    get_db_path,
    get_patches,
    get_rules,
    get_scans,
    get_threats,
    get_whitelist,
    init_db,
    insert_patch,
    insert_rule,
    insert_scan,
    insert_threat,
    insert_whitelist,
    migrate_from_jsonl,
    verify_audit_log,
)


# ---------------------------------------------------------------------------
# A. Database initialization
# ---------------------------------------------------------------------------

class TestDatabaseInit:
    def test_creates_db_file(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            db_path = get_db_path(tmp_path)
            assert db_path.exists()
        finally:
            conn.close()

    def test_creates_all_tables(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            table_names = {t[0] for t in tables}
            assert "threats" in table_names
            assert "rules" in table_names
            assert "whitelist" in table_names
            assert "scans" in table_names
            assert "patches" in table_names
            assert "audit_log" in table_names
        finally:
            conn.close()

    def test_idempotent_init(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn1 = init_db(tmp_path)
        conn1.close()
        conn2 = init_db(tmp_path)
        conn2.close()
        # Should not raise

    def test_context_manager(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        with get_connection(tmp_path) as conn:
            conn.execute("SELECT 1")


# ---------------------------------------------------------------------------
# B. Threats CRUD
# ---------------------------------------------------------------------------

class TestThreats:
    def test_insert_and_get(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            row_id = insert_threat(
                conn,
                hook_event="PreToolUse",
                tool_name="Bash",
                tool_input={"command": "rm -rf /"},
                decision="block",
                reason="Destructive command",
                category="destructive_shell",
                severity="critical",
                match_count=1,
            )
            assert row_id > 0

            threats = get_threats(conn)
            assert len(threats) == 1
            assert threats[0]["decision"] == "block"
            assert threats[0]["category"] == "destructive_shell"
        finally:
            conn.close()

    def test_filter_by_decision(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block", category="test")
            insert_threat(conn, hook_event="PreToolUse", tool_name="Read",
                          tool_input={}, decision="allow", category="test")

            blocks = get_threats(conn, decision="block")
            assert len(blocks) == 1
            allows = get_threats(conn, decision="allow")
            assert len(allows) == 1
        finally:
            conn.close()

    def test_count_threats(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block")
            insert_threat(conn, hook_event="PreToolUse", tool_name="Read",
                          tool_input={}, decision="block")
            insert_threat(conn, hook_event="PreToolUse", tool_name="Write",
                          tool_input={}, decision="allow")

            assert count_threats(conn) == 3
            assert count_threats(conn, decision="block") == 2
            assert count_threats(conn, decision="allow") == 1
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# C. Rules CRUD
# ---------------------------------------------------------------------------

class TestRules:
    def test_insert_and_get(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            row_id = insert_rule(conn, category="destructive_shell",
                                 pattern=r"rm\s+-rf")
            assert row_id > 0

            rules = get_rules(conn)
            assert len(rules) == 1
            assert rules[0]["category"] == "destructive_shell"

            # Filter by category
            rules = get_rules(conn, category="nonexistent")
            assert len(rules) == 0
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# D. Whitelist CRUD
# ---------------------------------------------------------------------------

class TestWhitelist:
    def test_insert_and_get(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_whitelist(conn, pattern="*.md", reason="Docs")
            insert_whitelist(conn, pattern="*.txt", pattern_type="glob")

            entries = get_whitelist(conn)
            assert len(entries) == 2
        finally:
            conn.close()

    def test_unique_constraint(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_whitelist(conn, pattern="*.md")
            insert_whitelist(conn, pattern="*.md")  # Duplicate, OR IGNORE

            entries = get_whitelist(conn)
            assert len(entries) == 1
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# E. Scans CRUD
# ---------------------------------------------------------------------------

class TestScans:
    def test_insert_and_get(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            scan_id = insert_scan(
                conn,
                scan_type="redteam",
                total_scenarios=10,
                passed=8,
                failed=2,
                score=80.0,
                grade="B",
                model_used="claude",
                details={"catch_rate": 80.0},
            )
            assert scan_id > 0

            scans = get_scans(conn)
            assert len(scans) == 1
            assert scans[0]["scan_type"] == "redteam"
            assert scans[0]["score"] == 80.0
        finally:
            conn.close()

    def test_filter_by_type(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_scan(conn, scan_type="audit", score=90.0)
            insert_scan(conn, scan_type="redteam", score=80.0)

            audits = get_scans(conn, scan_type="audit")
            assert len(audits) == 1
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# F. Patches CRUD
# ---------------------------------------------------------------------------

class TestPatches:
    def test_insert_and_get(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            patch_id = insert_patch(
                conn,
                category="destructive_shell",
                patterns_added=[r"rm\s+--force", r"mkfs\.\w+"],
                explanation="Catch rm --force and mkfs",
            )
            assert patch_id > 0

            patches = get_patches(conn)
            assert len(patches) == 1
            assert patches[0]["category"] == "destructive_shell"
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# G. Audit log with SHA-256 chain
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_entries_have_hashes(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            # Inserting a threat also creates audit log entries
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block", category="test")

            log = get_audit_log(conn)
            assert len(log) >= 1
            assert log[0]["entry_hash"] != ""
            assert log[0]["previous_hash"] != ""
        finally:
            conn.close()

    def test_chain_integrity(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            # Insert multiple events to build a chain
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block", category="a")
            insert_threat(conn, hook_event="PreToolUse", tool_name="Read",
                          tool_input={}, decision="allow", category="b")
            insert_scan(conn, scan_type="audit", score=95.0, grade="A")

            is_valid, count, error = verify_audit_log(conn)
            assert is_valid is True
            assert count >= 3
            assert error == ""
        finally:
            conn.close()

    def test_tamper_detection(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block", category="test")
            insert_threat(conn, hook_event="PreToolUse", tool_name="Read",
                          tool_input={}, decision="allow", category="test2")

            # Tamper with the audit log
            conn.execute(
                "UPDATE audit_log SET event_data = '{\"tampered\": true}' WHERE id = 1"
            )
            conn.commit()

            is_valid, _, error = verify_audit_log(conn)
            assert is_valid is False
            assert "mismatch" in error
        finally:
            conn.close()

    def test_filter_by_event_type(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            insert_threat(conn, hook_event="PreToolUse", tool_name="Bash",
                          tool_input={}, decision="block")
            insert_scan(conn, scan_type="audit", score=90.0)

            threat_logs = get_audit_log(conn, event_type="threat_detected")
            scan_logs = get_audit_log(conn, event_type="scan_completed")
            assert len(threat_logs) >= 1
            assert len(scan_logs) >= 1
        finally:
            conn.close()

    def test_empty_log_is_valid(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        conn = init_db(tmp_path)
        try:
            is_valid, count, error = verify_audit_log(conn)
            assert is_valid is True
            assert count == 0
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# H. JSONL Migration
# ---------------------------------------------------------------------------

class TestMigration:
    def test_migrate_from_jsonl(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        log_dir = bf_dir / "logs"
        log_dir.mkdir()

        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "hook_event": "PreToolUse",
             "tool_name": "Bash", "tool_input_summary": "test cmd",
             "decision": "block", "reason": "test", "match_count": 1},
            {"timestamp": "2026-01-01T00:01:00Z", "hook_event": "PreToolUse",
             "tool_name": "Read", "tool_input_summary": "/etc/passwd",
             "decision": "allow", "reason": "", "match_count": 0},
        ]
        jsonl_path = log_dir / "events.jsonl"
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        imported = migrate_from_jsonl(tmp_path)
        assert imported == 2

        # Verify imported data
        with get_connection(tmp_path) as conn:
            threats = get_threats(conn)
            assert len(threats) == 2

    def test_migrate_empty_file(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        log_dir = bf_dir / "logs"
        log_dir.mkdir()
        (log_dir / "events.jsonl").write_text("", encoding="utf-8")

        imported = migrate_from_jsonl(tmp_path)
        assert imported == 0

    def test_migrate_no_file(self, tmp_path: Path) -> None:
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()

        imported = migrate_from_jsonl(tmp_path)
        assert imported == 0
