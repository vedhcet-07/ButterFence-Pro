"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from butterfence.scoring import ScoreResult


def generate_report(
    score_result: ScoreResult,
    audit_results: list[dict],
    output_path: Path | None = None,
) -> str:
    """Generate a structured markdown safety report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# ButterFence Safety Report",
        "",
        f"**Generated:** {now}",
        "",
        "---",
        "",
        "## Score",
        "",
        f"**{score_result.total_score}/{score_result.max_score}** | Grade: **{score_result.grade}** ({score_result.grade_label})",
        "",
    ]

    # Score badge
    if score_result.total_score >= 90:
        lines.append("> Your repo is **hardened** against common agent threats.")
    elif score_result.total_score >= 70:
        lines.append("> Your repo is **mostly safe** but has some gaps to address.")
    elif score_result.total_score >= 50:
        lines.append("> Your repo has **significant risks** that need attention.")
    else:
        lines.append("> Your repo is **unsafe for autonomous agent use**. Immediate action required.")
    lines.append("")

    # Results table
    lines.extend([
        "---",
        "",
        "## Scenario Results",
        "",
        "| Status | ID | Name | Category | Severity | Expected | Actual |",
        "|--------|----|------|----------|----------|----------|--------|",
    ])

    for r in audit_results:
        status = "PASS" if r.get("passed", False) else "FAIL"
        lines.append(
            f"| {status} | {r['id']} | {r['name']} | {r['category']} | "
            f"{r['severity']} | {r['expected_decision']} | {r['actual_decision']} |"
        )
    lines.append("")

    # Deductions
    if score_result.deductions:
        lines.extend([
            "---",
            "",
            "## Deductions",
            "",
            "| Scenario | Category | Severity | Points | Reason |",
            "|----------|----------|----------|--------|--------|",
        ])
        for d in score_result.deductions:
            lines.append(
                f"| {d['scenario']} | {d['category']} | {d['severity']} | "
                f"{d['points']} | {d.get('reason', 'Scenario failed')} |"
            )
        lines.append("")

    # Category coverage
    lines.extend([
        "---",
        "",
        "## Category Coverage",
        "",
        "| Category | Total | Passed | Failed |",
        "|----------|-------|--------|--------|",
    ])
    for cat, stats in score_result.category_coverage.items():
        lines.append(
            f"| {cat} | {stats['total']} | {stats['passed']} | {stats['failed']} |"
        )
    lines.append("")

    # Recommendations
    lines.extend([
        "---",
        "",
        "## Recommendations",
        "",
    ])
    for rec in score_result.recommendations:
        lines.append(f"- {rec}")
    lines.append("")

    report_text = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text, encoding="utf-8")

    return report_text


def generate_html_report(
    score_result: ScoreResult,
    audit_results: list[dict],
    output_path: Path | None = None,
) -> str:
    """Generate a styled standalone HTML safety report."""
    import html as html_mod

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = score_result.total_score
    grade = score_result.grade
    label = score_result.grade_label

    # Score color
    if score >= 90:
        score_color = "#10b981"
        score_bg = "rgba(16,185,129,0.12)"
    elif score >= 70:
        score_color = "#f59e0b"
        score_bg = "rgba(245,158,11,0.12)"
    elif score >= 50:
        score_color = "#f97316"
        score_bg = "rgba(249,115,22,0.12)"
    else:
        score_color = "#ef4444"
        score_bg = "rgba(239,68,68,0.12)"

    # Build scenario rows
    scenario_rows = ""
    for r in audit_results:
        passed = r.get("passed", False)
        status_class = "pass" if passed else "fail"
        status_text = "PASS" if passed else "FAIL"
        sev = r.get("severity", "").lower()
        sev_class = "critical" if sev == "critical" else "high" if sev == "high" else "medium"
        scenario_rows += f"""
            <tr>
                <td><span class="badge {status_class}">{status_text}</span></td>
                <td class="mono">{html_mod.escape(r.get('id', ''))}</td>
                <td>{html_mod.escape(r.get('name', ''))}</td>
                <td>{html_mod.escape(r.get('category', ''))}</td>
                <td><span class="badge {sev_class}">{html_mod.escape(sev.upper())}</span></td>
                <td>{html_mod.escape(r.get('expected_decision', ''))}</td>
                <td>{html_mod.escape(r.get('actual_decision', ''))}</td>
            </tr>"""

    # Build deductions rows
    deduction_section = ""
    if score_result.deductions:
        deduction_rows = ""
        for d in score_result.deductions:
            deduction_rows += f"""
                <tr>
                    <td>{html_mod.escape(d.get('scenario', ''))}</td>
                    <td>{html_mod.escape(d.get('category', ''))}</td>
                    <td>{html_mod.escape(d.get('severity', ''))}</td>
                    <td class="mono">{d.get('points', 0)}</td>
                    <td>{html_mod.escape(d.get('reason', 'Scenario failed'))}</td>
                </tr>"""
        deduction_section = f"""
        <div class="card">
            <h2>⚠️ Deductions</h2>
            <table>
                <thead><tr><th>Scenario</th><th>Category</th><th>Severity</th><th>Points</th><th>Reason</th></tr></thead>
                <tbody>{deduction_rows}</tbody>
            </table>
        </div>"""

    # Build category coverage rows
    cat_rows = ""
    for cat, stats in score_result.category_coverage.items():
        failed = stats.get("failed", 0)
        row_class = ' class="fail-row"' if failed > 0 else ""
        cat_rows += f"""
            <tr{row_class}>
                <td>{html_mod.escape(cat)}</td>
                <td>{stats.get('total', 0)}</td>
                <td>{stats.get('passed', 0)}</td>
                <td>{failed}</td>
            </tr>"""

    # Recommendations
    rec_items = ""
    for rec in score_result.recommendations:
        rec_items += f"<li>{html_mod.escape(rec)}</li>\n"

    # Gauge arc
    pct = min(score, 100)
    circ = 2 * 3.14159 * 70
    offset = circ - (pct / 100) * circ

    passed_count = sum(1 for r in audit_results if r.get("passed"))
    failed_count = len(audit_results) - passed_count

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ButterFence Safety Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;line-height:1.6;padding:40px 20px}}
.container{{max-width:1100px;margin:0 auto}}
.header{{text-align:center;margin-bottom:48px}}
.header h1{{font-size:2.2rem;font-weight:800;background:linear-gradient(135deg,#a78bfa,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
.header .subtitle{{color:#94a3b8;font-size:0.95rem}}
.header .brand{{font-size:1rem;color:#64748b;margin-bottom:20px;display:flex;align-items:center;justify-content:center;gap:8px}}
.header .brand span{{font-size:1.3rem}}
.score-section{{display:flex;gap:24px;justify-content:center;flex-wrap:wrap;margin-bottom:40px}}
.score-card{{background:#111827;border-radius:16px;padding:32px;text-align:center;border:1px solid rgba(255,255,255,0.06);min-width:200px}}
.gauge{{position:relative;display:inline-block}}
.gauge svg{{transform:rotate(-90deg)}}
.gauge-bg{{fill:none;stroke:#1e293b;stroke-width:10}}
.gauge-fill{{fill:none;stroke:{score_color};stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1s ease}}
.gauge-text{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}}
.gauge-value{{font-size:2rem;font-weight:800;color:{score_color}}}
.gauge-label{{color:#94a3b8;font-size:0.85rem;margin-top:-2px}}
.stat-card{{background:#111827;border-radius:16px;padding:24px;text-align:center;border:1px solid rgba(255,255,255,0.06)}}
.stat-card .value{{font-size:2rem;font-weight:800}}
.stat-card .label{{color:#94a3b8;font-size:0.85rem;margin-top:4px}}
.stat-card.pass .value{{color:#10b981}}
.stat-card.fail .value{{color:#ef4444}}
.stat-card.total .value{{color:#a78bfa}}
.grade-pill{{display:inline-block;background:{score_bg};color:{score_color};padding:6px 20px;border-radius:99px;font-weight:700;font-size:1.1rem;margin-top:12px;border:1px solid {score_color}33}}
.card{{background:#111827;border-radius:16px;padding:28px;margin-bottom:24px;border:1px solid rgba(255,255,255,0.06)}}
.card h2{{font-size:1.2rem;font-weight:700;margin-bottom:16px;color:#f1f5f9}}
table{{width:100%;border-collapse:collapse;font-size:0.88rem}}
thead th{{text-align:left;padding:10px 12px;color:#94a3b8;font-weight:600;border-bottom:1px solid #1e293b;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.5px}}
tbody td{{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,0.04)}}
tbody tr:hover{{background:rgba(255,255,255,0.02)}}
.fail-row td{{background:rgba(239,68,68,0.06)}}
.mono{{font-family:'Fira Code',monospace;font-size:0.82rem;color:#94a3b8}}
.badge{{display:inline-block;padding:2px 10px;border-radius:6px;font-weight:600;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.3px}}
.badge.pass{{background:rgba(16,185,129,0.15);color:#10b981}}
.badge.fail{{background:rgba(239,68,68,0.15);color:#ef4444}}
.badge.critical{{background:rgba(239,68,68,0.15);color:#ef4444}}
.badge.high{{background:rgba(249,115,22,0.15);color:#f97316}}
.badge.medium{{background:rgba(245,158,11,0.15);color:#f59e0b}}
ul{{padding-left:20px}}
li{{margin-bottom:8px;color:#cbd5e1}}
.footer{{text-align:center;color:#475569;font-size:0.8rem;margin-top:48px;padding-top:24px;border-top:1px solid #1e293b}}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <div class="brand"><span>🛡️</span> ButterFence Pro</div>
    <h1>Security Safety Report</h1>
    <p class="subtitle">Generated {now}</p>
</div>

<div class="score-section">
    <div class="score-card">
        <div class="gauge">
            <svg width="180" height="180" viewBox="0 0 180 180">
                <circle class="gauge-bg" cx="90" cy="90" r="70"/>
                <circle class="gauge-fill" cx="90" cy="90" r="70"
                    style="stroke-dasharray:{circ:.1f};stroke-dashoffset:{offset:.1f}"/>
            </svg>
            <div class="gauge-text">
                <div class="gauge-value">{score}</div>
                <div class="gauge-label">/ {score_result.max_score}</div>
            </div>
        </div>
        <div class="grade-pill">Grade {grade} — {label}</div>
    </div>
    <div style="display:flex;flex-direction:column;gap:16px;justify-content:center">
        <div class="stat-card total"><div class="value">{len(audit_results)}</div><div class="label">Total Scenarios</div></div>
        <div class="stat-card pass"><div class="value">{passed_count}</div><div class="label">Passed</div></div>
        <div class="stat-card fail"><div class="value">{failed_count}</div><div class="label">Failed</div></div>
    </div>
</div>

<div class="card">
    <h2>📋 Scenario Results</h2>
    <table>
        <thead><tr><th>Status</th><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Expected</th><th>Actual</th></tr></thead>
        <tbody>{scenario_rows}</tbody>
    </table>
</div>

{deduction_section}

<div class="card">
    <h2>📊 Category Coverage</h2>
    <table>
        <thead><tr><th>Category</th><th>Total</th><th>Passed</th><th>Failed</th></tr></thead>
        <tbody>{cat_rows}</tbody>
    </table>
</div>

<div class="card">
    <h2>💡 Recommendations</h2>
    <ul>{rec_items}</ul>
</div>

<div class="footer">
    ButterFence Pro v0.3.2 — Claude Code Safety Harness<br>
    Report generated {now}
</div>

</div>
</body>
</html>"""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")

    return html_content
