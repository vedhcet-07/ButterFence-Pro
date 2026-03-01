"""Tests for the ButterFence REST API layer."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

# Skip all tests if fastapi/httpx are not installed
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from butterfence.api import create_app
from butterfence.api.auth_middleware import DEFAULT_DEV_KEY


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    """Create a minimal project directory with config."""
    bf_dir = tmp_path / ".butterfence"
    bf_dir.mkdir()

    config_dir = bf_dir / "config"
    config_dir.mkdir()
    config_file = config_dir / "butterfence.yaml"
    config_file.write_text(
        "categories:\n"
        "  destructive_shell:\n"
        "    severity: critical\n"
        "    action: block\n"
        "    patterns:\n"
        "      - 'rm\\s+-rf\\s+/'\n",
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture()
def client(project_dir: Path) -> TestClient:
    """Create a test client with a temporary project."""
    app = create_app(project_dir)
    return TestClient(app)


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    """Valid auth headers using the default dev key."""
    return {"X-API-Key": DEFAULT_DEV_KEY}


# ---------------------------------------------------------------------------
# A. Health endpoint (no auth required)
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "butterfence-api"


# ---------------------------------------------------------------------------
# B. Authentication
# ---------------------------------------------------------------------------

class TestAuth:
    def test_missing_key_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/threats")
        assert resp.status_code == 401

    def test_invalid_key_returns_403(self, client: TestClient) -> None:
        resp = client.get(
            "/api/threats",
            headers={"X-API-Key": "invalid-key-12345"},
        )
        assert resp.status_code == 403

    def test_valid_key_succeeds(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/api/threats", headers=auth_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# C. POST /api/intercept
# ---------------------------------------------------------------------------

class TestIntercept:
    def test_allow_safe_command(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/api/intercept",
            json={"tool_name": "Read", "tool_input": {"file_path": "README.md"}},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] in ("allow", "warn", "block")

    def test_block_dangerous_command(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/api/intercept",
            json={
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
                "hook_event": "PreToolUse",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "block"
        assert data["match_count"] > 0


# ---------------------------------------------------------------------------
# D. GET /api/threats
# ---------------------------------------------------------------------------

class TestThreats:
    def test_empty_threats(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/api/threats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["threats"] == []

    def test_threats_after_intercept(
        self, client: TestClient, auth_headers: dict, project_dir: Path
    ) -> None:
        # Insert a threat directly
        from butterfence.database import init_db, insert_threat

        conn = init_db(project_dir)
        try:
            insert_threat(
                conn,
                hook_event="PreToolUse",
                tool_name="Bash",
                tool_input={"command": "rm -rf /"},
                decision="block",
                reason="Test threat",
                category="destructive_shell",
                severity="critical",
                match_count=1,
            )
        finally:
            conn.close()

        resp = client.get("/api/threats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1


# ---------------------------------------------------------------------------
# E. POST /api/supply-chain/scan
# ---------------------------------------------------------------------------

class TestSupplyChainAPI:
    def test_scan_clean_project(
        self, client: TestClient, auth_headers: dict, project_dir: Path
    ) -> None:
        # Create a clean requirements.txt
        req = project_dir / "requirements.txt"
        req.write_text("requests\nflask\n", encoding="utf-8")

        resp = client.post(
            "/api/supply-chain/scan",
            json={"project_dir": str(project_dir)},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_issues"] == 0

    def test_scan_with_typosquat(
        self, client: TestClient, auth_headers: dict, project_dir: Path
    ) -> None:
        req = project_dir / "requirements.txt"
        req.write_text("requets\nnumpy\n", encoding="utf-8")

        resp = client.post(
            "/api/supply-chain/scan",
            json={"project_dir": str(project_dir)},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_issues"] >= 1


# ---------------------------------------------------------------------------
# F. GET /api/audit-log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_empty_log(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/api/audit-log", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["entries"], list)

    def test_verify_chain(
        self, client: TestClient, auth_headers: dict, project_dir: Path
    ) -> None:
        # Insert some data to populate audit log
        from butterfence.database import init_db, insert_threat

        conn = init_db(project_dir)
        try:
            insert_threat(
                conn, hook_event="PreToolUse", tool_name="Bash",
                tool_input={}, decision="block", category="test",
            )
        finally:
            conn.close()

        resp = client.get(
            "/api/audit-log",
            params={"verify": True},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_valid"] is True


# ---------------------------------------------------------------------------
# G. PUT /api/rules/whitelist
# ---------------------------------------------------------------------------

class TestWhitelistAPI:
    def test_add_whitelist(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(
            "/api/rules/whitelist",
            json={"pattern": "*.md", "reason": "docs"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"]
        assert data["id"] >= 0


# ---------------------------------------------------------------------------
# H. POST /api/rules/custom
# ---------------------------------------------------------------------------

class TestCustomRules:
    def test_add_custom_rule(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/api/rules/custom",
            json={
                "category": "test_category",
                "pattern": "test_pattern",
                "action": "block",
                "severity": "high",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] > 0


# ---------------------------------------------------------------------------
# I. POST /api/patch/generate
# ---------------------------------------------------------------------------

class TestPatch:
    def test_patch_generate(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/api/patch/generate",
            json={"category": "test"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "message" in data


# ---------------------------------------------------------------------------
# J. GET /api/report/export
# ---------------------------------------------------------------------------

class TestReportExport:
    def test_markdown_export(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            "/api/report/export",
            params={"format": "markdown"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "markdown"
