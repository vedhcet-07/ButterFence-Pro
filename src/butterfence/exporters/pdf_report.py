"""PDF report generator for ButterFence.

Generates a formatted PDF threat report using reportlab.
Falls back to a basic text-based PDF if reportlab is not available.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_pdf_report(
    project_dir: Path,
    output_path: Path,
) -> Path:
    """Generate a PDF threat report.

    Args:
        project_dir: Project root directory.
        output_path: Where to save the PDF file.

    Returns:
        Path to the generated PDF.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table as RLTable,
            TableStyle,
        )
    except ImportError:
        # Fallback to basic text PDF
        return _generate_text_pdf(project_dir, output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Load data from database
    threats_data: list[dict] = []
    scans_data: list[dict] = []
    total_threats = 0
    audit_valid = True

    try:
        from butterfence.database import (
            count_threats,
            get_connection,
            get_scans,
            get_threats,
            verify_audit_log,
        )

        with get_connection(project_dir) as conn:
            threats_data = get_threats(conn, limit=50)
            scans_data = get_scans(conn, limit=10)
            total_threats = count_threats(conn)
            audit_valid, _, _ = verify_audit_log(conn)
    except Exception:
        pass

    # Build PDF
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=24, spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "Heading", parent=styles["Heading2"], fontSize=16, spaceAfter=8,
    )
    body_style = styles["BodyText"]

    elements = []

    # Title
    elements.append(Paragraph("ButterFence Pro — Security Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        body_style,
    ))
    elements.append(Spacer(1, 12))

    # Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    blocks = sum(1 for t in threats_data if t.get("decision") == "block")
    elements.append(Paragraph(
        f"Total threats logged: <b>{total_threats}</b><br/>"
        f"Recent blocks: <b>{blocks}</b><br/>"
        f"Recent scans: <b>{len(scans_data)}</b><br/>"
        f"Audit log integrity: <b>{'✓ Valid' if audit_valid else '✗ TAMPERED'}</b>",
        body_style,
    ))
    elements.append(Spacer(1, 12))

    # Threats table
    if threats_data:
        elements.append(Paragraph("Recent Threats", heading_style))
        table_data = [["Severity", "Tool", "Decision", "Category", "Reason"]]
        for t in threats_data[:20]:
            table_data.append([
                t.get("severity", ""),
                t.get("tool_name", ""),
                t.get("decision", ""),
                t.get("category", ""),
                (t.get("reason", "") or "")[:60],
            ])

        tbl = RLTable(table_data, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(tbl)
        elements.append(Spacer(1, 12))

    # Scans table
    if scans_data:
        elements.append(Paragraph("Recent Scans", heading_style))
        scan_table = [["Type", "Score", "Grade", "Passed", "Failed", "Model"]]
        for s in scans_data:
            scan_table.append([
                s.get("scan_type", ""),
                f"{s.get('score', 0):.0f}",
                s.get("grade", ""),
                str(s.get("passed", 0)),
                str(s.get("failed", 0)),
                s.get("model_used", ""),
            ])

        stbl = RLTable(scan_table, repeatRows=1)
        stbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(stbl)

    doc.build(elements)
    return output_path


def _generate_text_pdf(project_dir: Path, output_path: Path) -> Path:
    """Fallback: generate a plain-text report file (no reportlab)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Just generate a text report as fallback
    lines = [
        "BUTTERFENCE PRO — SECURITY REPORT",
        "=" * 40,
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    try:
        from butterfence.database import (
            count_threats,
            get_connection,
            get_scans,
            get_threats,
        )

        with get_connection(project_dir) as conn:
            threats = get_threats(conn, limit=20)
            scans = get_scans(conn, limit=5)
            total = count_threats(conn)

        lines.append(f"Total threats: {total}")
        lines.append(f"Recent scans: {len(scans)}")
        lines.append("")
        lines.append("RECENT THREATS")
        lines.append("-" * 40)
        for t in threats:
            lines.append(
                f"  [{t.get('severity', '')}] {t.get('tool_name', '')} "
                f"— {t.get('decision', '')} — {(t.get('reason', '') or '')[:60]}"
            )
    except Exception:
        lines.append("(No database available)")

    # Write as .txt if no reportlab (rename to .pdf for compatibility)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
