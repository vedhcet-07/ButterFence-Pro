"""API routes — 10 endpoints for ButterFence REST API."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from butterfence.api.auth_middleware import require_admin, require_api_key
from butterfence.api.schemas import (
    AuditLogResponse,
    AuditLogEntry,
    CustomRuleRequest,
    CustomRuleResponse,
    InterceptRequest,
    InterceptResponse,
    PatchGenerateRequest,
    PatchResponse,
    RedTeamResultResponse,
    RedTeamStartRequest,
    RedTeamStartResponse,
    ReportExportResponse,
    SupplyChainResponse,
    SupplyChainScanRequest,
    SupplyChainFindingSchema,
    ThreatSchema,
    ThreatsResponse,
    WhitelistAddRequest,
    WhitelistResponse,
)

router = APIRouter()


def _get_project_dir(request: Request) -> Path:
    """Get the project directory from app state."""
    return request.app.state.project_dir


# ---------------------------------------------------------------------------
# 1. POST /intercept — Evaluate a command
# ---------------------------------------------------------------------------

@router.post("/intercept", response_model=InterceptResponse)
async def intercept(
    body: InterceptRequest,
    request: Request,
    _key: str = Depends(require_api_key),
):
    """Evaluate a tool use command against ButterFence rules."""
    project_dir = _get_project_dir(request)

    from butterfence.config import load_config
    from butterfence.matcher import HookPayload, match_rules

    config = load_config(project_dir)
    payload = HookPayload(
        hook_event=body.hook_event,
        tool_name=body.tool_name,
        tool_input=body.tool_input,
    )

    result = match_rules(payload, config)

    matches = [
        {
            "category": m.category,
            "severity": m.severity,
            "action": m.action,
            "pattern": m.pattern,
            "matched_text": m.matched_text[:200],
        }
        for m in result.matches
    ]

    return InterceptResponse(
        decision=result.decision,
        reason=result.reason,
        matches=matches,
        match_count=len(result.matches),
    )


# ---------------------------------------------------------------------------
# 2. POST /redteam/start — Launch red team scan
# ---------------------------------------------------------------------------

@router.post("/redteam/start", response_model=RedTeamStartResponse)
async def redteam_start(
    body: RedTeamStartRequest,
    request: Request,
    _key: str = Depends(require_api_key),
):
    """Start a red team assessment (runs synchronously for now)."""
    project_dir = _get_project_dir(request)

    from butterfence.config import load_config
    from butterfence.database import get_connection, insert_scan

    config = load_config(project_dir)

    try:
        if body.models and len(body.models) > 0:
            from butterfence.redteam import run_multi_model_redteam
            result = run_multi_model_redteam(
                config=config,
                target_dir=project_dir,
                models=body.models,
                count=body.count,
                categories=body.categories,
            )
        else:
            from butterfence.redteam import run_redteam
            result = run_redteam(
                config=config,
                target_dir=project_dir,
                count=body.count,
                model=body.model,
                categories=body.categories,
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Store in database
    try:
        with get_connection(project_dir) as conn:
            scan_id = insert_scan(
                conn,
                scan_type="redteam",
                total_scenarios=result.scenarios_run,
                passed=result.caught,
                failed=result.missed,
                score=result.catch_rate,
                grade="A" if result.catch_rate >= 90 else "B" if result.catch_rate >= 70 else "C",
                model_used=result.model_used,
                details={
                    "raw_scenarios": result.raw_scenarios,
                    "results": [
                        {"id": r.id, "name": r.name, "category": r.category,
                         "severity": r.severity, "passed": r.passed}
                        for r in result.results
                    ],
                },
            )
    except Exception:
        scan_id = 0

    return RedTeamStartResponse(
        scan_id=scan_id,
        status="completed",
        message=f"Generated {result.scenarios_run} scenarios, {result.caught} caught, {result.missed} missed",
    )


# ---------------------------------------------------------------------------
# 3. GET /redteam/{scan_id} — Poll results
# ---------------------------------------------------------------------------

@router.get("/redteam/{scan_id}", response_model=RedTeamResultResponse)
async def redteam_result(
    scan_id: int,
    request: Request,
    _key: str = Depends(require_api_key),
):
    """Get red team scan results by scan ID."""
    project_dir = _get_project_dir(request)

    from butterfence.database import get_connection

    try:
        with get_connection(project_dir) as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if not row:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    r = dict(row)
    details = {}
    try:
        details = json.loads(r.get("details_json", "{}"))
    except json.JSONDecodeError:
        pass

    return RedTeamResultResponse(
        scan_id=r["id"],
        status="completed",
        scan_type=r.get("scan_type", "redteam"),
        total_scenarios=r.get("total_scenarios", 0),
        passed=r.get("passed", 0),
        failed=r.get("failed", 0),
        score=r.get("score", 0.0),
        grade=r.get("grade", ""),
        model_used=r.get("model_used", ""),
        details=details,
    )


# ---------------------------------------------------------------------------
# 4. POST /supply-chain/scan — Scan dependencies
# ---------------------------------------------------------------------------

@router.post("/supply-chain/scan", response_model=SupplyChainResponse)
async def supply_chain_scan(
    body: SupplyChainScanRequest,
    request: Request,
    _key: str = Depends(require_api_key),
):
    """Scan project dependencies for supply chain threats."""
    project_dir = Path(body.project_dir) if body.project_dir else _get_project_dir(request)

    from butterfence.supply_chain import scan_supply_chain

    result = scan_supply_chain(project_dir)

    findings = [
        SupplyChainFindingSchema(
            package=f.package,
            source_file=f.source_file,
            severity=f.severity,
            reason=f.reason,
            safe_alternative=f.safe_alternative,
            line_number=f.line_number,
        )
        for f in result.findings
    ]

    return SupplyChainResponse(
        files_scanned=result.files_scanned,
        packages_checked=result.packages_checked,
        total_issues=result.total_issues,
        typosquats_found=result.typosquats_found,
        malicious_found=result.malicious_found,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# 5. GET /threats — List threats
# ---------------------------------------------------------------------------

@router.get("/threats", response_model=ThreatsResponse)
async def list_threats(
    request: Request,
    decision: str | None = None,
    category: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _key: str = Depends(require_api_key),
):
    """List threat interception records from the database."""
    project_dir = _get_project_dir(request)

    from butterfence.database import count_threats, get_connection, get_threats

    try:
        with get_connection(project_dir) as conn:
            threats = get_threats(
                conn, decision=decision, category=category,
                limit=limit, offset=offset,
            )
            total = count_threats(conn, decision=decision)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return ThreatsResponse(
        total=total,
        threats=[
            ThreatSchema(
                id=t["id"],
                timestamp=t.get("timestamp", ""),
                hook_event=t.get("hook_event", ""),
                tool_name=t.get("tool_name", ""),
                decision=t.get("decision", ""),
                reason=t.get("reason", ""),
                category=t.get("category", ""),
                severity=t.get("severity", ""),
                match_count=t.get("match_count", 0),
            )
            for t in threats
        ],
    )


# ---------------------------------------------------------------------------
# 6. POST /patch/generate — Auto-patch
# ---------------------------------------------------------------------------

@router.post("/patch/generate", response_model=PatchResponse)
async def patch_generate(
    body: PatchGenerateRequest,
    request: Request,
    _key: str = Depends(require_admin),
):
    """Generate and apply AI-suggested patches for missed scenarios."""
    project_dir = _get_project_dir(request)

    # This is a placeholder — real implementation requires a scan with missed scenarios
    from butterfence.database import get_connection, insert_patch

    try:
        with get_connection(project_dir) as conn:
            patch_id = insert_patch(
                conn,
                category=body.category or "general",
                patterns_added=[],
                explanation="Placeholder — run via CLI for full functionality",
                source_scan_id=body.scan_id,
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return PatchResponse(
        patches_applied=0,
        message=f"Patch record {patch_id} created. Use CLI `butterfence redteam --fix` for AI-generated patches.",
    )


# ---------------------------------------------------------------------------
# 7. GET /audit-log — Tamper-evident log
# ---------------------------------------------------------------------------

@router.get("/audit-log", response_model=AuditLogResponse)
async def audit_log(
    request: Request,
    event_type: str | None = None,
    limit: int = 100,
    verify: bool = False,
    _key: str = Depends(require_api_key),
):
    """Get the tamper-evident audit log with optional integrity verification."""
    project_dir = _get_project_dir(request)

    from butterfence.database import get_audit_log, get_connection, verify_audit_log

    try:
        with get_connection(project_dir) as conn:
            entries_raw = get_audit_log(conn, event_type=event_type, limit=limit)

            chain_valid = True
            entries_checked = 0
            if verify:
                chain_valid, entries_checked, _ = verify_audit_log(conn)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    entries = []
    for e in entries_raw:
        try:
            event_data = json.loads(e.get("event_data", "{}"))
        except (json.JSONDecodeError, TypeError):
            event_data = {}

        entries.append(AuditLogEntry(
            id=e["id"],
            timestamp=e.get("timestamp", ""),
            event_type=e.get("event_type", ""),
            event_data=event_data,
            entry_hash=e.get("entry_hash", ""),
        ))

    return AuditLogResponse(
        entries=entries,
        chain_valid=chain_valid,
        entries_checked=entries_checked,
    )


# ---------------------------------------------------------------------------
# 8. PUT /rules/whitelist — Add whitelist pattern
# ---------------------------------------------------------------------------

@router.put("/rules/whitelist", response_model=WhitelistResponse)
async def add_whitelist(
    body: WhitelistAddRequest,
    request: Request,
    _key: str = Depends(require_admin),
):
    """Add a whitelist pattern to reduce false positives."""
    project_dir = _get_project_dir(request)

    from butterfence.database import get_connection, get_whitelist, insert_whitelist

    try:
        with get_connection(project_dir) as conn:
            wl_id = insert_whitelist(
                conn,
                pattern=body.pattern,
                pattern_type=body.pattern_type,
                reason=body.reason,
            )
            all_entries = get_whitelist(conn)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return WhitelistResponse(
        id=wl_id,
        message=f"Whitelist pattern '{body.pattern}' added",
        entries=all_entries,
    )


# ---------------------------------------------------------------------------
# 9. GET /report/export — PDF/Markdown export
# ---------------------------------------------------------------------------

@router.get("/report/export", response_model=ReportExportResponse)
async def report_export(
    request: Request,
    format: str = "markdown",
    _key: str = Depends(require_api_key),
):
    """Export a security report."""
    project_dir = _get_project_dir(request)

    if format == "pdf":
        try:
            from butterfence.exporters.pdf_report import generate_pdf_report
            report_path = project_dir / ".butterfence" / "reports" / "threat_report.pdf"
            generate_pdf_report(project_dir, report_path)
            return ReportExportResponse(
                format="pdf",
                path=str(report_path),
                message="PDF report generated",
            )
        except ImportError:
            return ReportExportResponse(
                format="pdf",
                message="PDF export requires reportlab. Install: pip install butterfence[pdf]",
            )
    else:
        # Markdown export using existing report module
        try:
            from butterfence.database import get_connection, get_scans, get_threats, count_threats
            with get_connection(project_dir) as conn:
                threats = get_threats(conn, limit=50)
                scans = get_scans(conn, limit=10)
                total = count_threats(conn)

            report_path = project_dir / ".butterfence" / "reports" / "api_report.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)

            lines = [
                "# ButterFence Security Report\n",
                f"\n## Summary\n- Total threats: {total}\n",
                f"- Recent scans: {len(scans)}\n",
                "\n## Recent Threats\n",
            ]
            for t in threats[:20]:
                lines.append(
                    f"- [{t.get('severity', 'unknown')}] {t.get('tool_name', '')} — "
                    f"{t.get('decision', '')} — {t.get('reason', '')[:80]}\n"
                )

            report_path.write_text("".join(lines), encoding="utf-8")

            return ReportExportResponse(
                format="markdown",
                path=str(report_path),
                message="Markdown report generated",
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# 10. POST /rules/custom — Upload custom rule
# ---------------------------------------------------------------------------

@router.post("/rules/custom", response_model=CustomRuleResponse)
async def add_custom_rule(
    body: CustomRuleRequest,
    request: Request,
    _key: str = Depends(require_admin),
):
    """Add a custom detection rule."""
    project_dir = _get_project_dir(request)

    from butterfence.database import get_connection, insert_rule

    try:
        with get_connection(project_dir) as conn:
            rule_id = insert_rule(
                conn,
                category=body.category,
                pattern=body.pattern,
                action=body.action,
                severity=body.severity,
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return CustomRuleResponse(
        id=rule_id,
        message=f"Custom rule added: {body.category}/{body.pattern}",
    )
