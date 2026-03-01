"""Pydantic request/response schemas for the ButterFence API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Intercept
# ---------------------------------------------------------------------------

class InterceptRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being used")
    tool_input: dict[str, Any] = Field(default_factory=dict, description="Tool input data")
    hook_event: str = Field(default="PreToolUse", description="Hook event type")


class InterceptResponse(BaseModel):
    decision: str = Field(..., description="block, warn, or allow")
    reason: str = Field(default="", description="Reason for the decision")
    matches: list[dict[str, Any]] = Field(default_factory=list)
    match_count: int = Field(default=0)


# ---------------------------------------------------------------------------
# Red Team
# ---------------------------------------------------------------------------

class RedTeamStartRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=100, description="Number of scenarios")
    model: str = Field(default="claude-opus-4-6", description="Model to use")
    models: list[str] | None = Field(default=None, description="Multi-model list")
    categories: list[str] | None = Field(default=None, description="Filter categories")


class RedTeamStartResponse(BaseModel):
    scan_id: int = Field(..., description="Scan ID for polling")
    status: str = Field(default="started", description="Current status")
    message: str = Field(default="")


class RedTeamResultResponse(BaseModel):
    scan_id: int
    status: str
    scan_type: str = "redteam"
    total_scenarios: int = 0
    passed: int = 0
    failed: int = 0
    score: float = 0.0
    grade: str = ""
    model_used: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Supply Chain
# ---------------------------------------------------------------------------

class SupplyChainScanRequest(BaseModel):
    project_dir: str | None = Field(default=None, description="Project directory to scan")


class SupplyChainFindingSchema(BaseModel):
    package: str
    source_file: str
    severity: str
    reason: str
    safe_alternative: str = ""
    line_number: int = 0


class SupplyChainResponse(BaseModel):
    files_scanned: int = 0
    packages_checked: int = 0
    total_issues: int = 0
    typosquats_found: int = 0
    malicious_found: int = 0
    findings: list[SupplyChainFindingSchema] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------

class ThreatSchema(BaseModel):
    id: int
    timestamp: str
    hook_event: str = ""
    tool_name: str = ""
    decision: str = ""
    reason: str = ""
    category: str = ""
    severity: str = ""
    match_count: int = 0


class ThreatsResponse(BaseModel):
    total: int = 0
    threats: list[ThreatSchema] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

class AuditLogEntry(BaseModel):
    id: int
    timestamp: str
    event_type: str
    event_data: dict[str, Any] = Field(default_factory=dict)
    entry_hash: str = ""


class AuditLogResponse(BaseModel):
    entries: list[AuditLogEntry] = Field(default_factory=list)
    chain_valid: bool = True
    entries_checked: int = 0


# ---------------------------------------------------------------------------
# Patch
# ---------------------------------------------------------------------------

class PatchGenerateRequest(BaseModel):
    scan_id: int | None = Field(default=None, description="Source scan ID")
    category: str = Field(default="", description="Category to fix")


class PatchResponse(BaseModel):
    patches_applied: int = 0
    message: str = ""


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

class WhitelistAddRequest(BaseModel):
    pattern: str = Field(..., description="Glob/regex/exact pattern")
    pattern_type: str = Field(default="glob", description="Pattern type: glob, regex, exact")
    reason: str = Field(default="", description="Reason for whitelisting")


class WhitelistResponse(BaseModel):
    id: int = 0
    message: str = ""
    entries: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class CustomRuleRequest(BaseModel):
    category: str = Field(..., description="Rule category")
    pattern: str = Field(..., description="Regex pattern")
    action: str = Field(default="block", description="Action: block, warn, allow")
    severity: str = Field(default="high", description="Severity level")


class CustomRuleResponse(BaseModel):
    id: int = 0
    message: str = ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class ReportExportResponse(BaseModel):
    format: str = "pdf"
    path: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    detail: str
    error_code: str = "INTERNAL_ERROR"
