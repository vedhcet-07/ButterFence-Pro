"""Self-contained HTML report with inline CSS, SVG gauge, and dark theme."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from butterfence import __version__
from butterfence.scoring import ScoreResult


def _grade_color(grade: str) -> str:
    return {"A": "#10b981", "B": "#f59e0b", "C": "#f97316", "D": "#ef4444", "F": "#ef4444"}.get(
        grade, "#6b7280"
    )


def _grade_bg(grade: str) -> str:
    return {
        "A": "rgba(16,185,129,0.12)",
        "B": "rgba(245,158,11,0.12)",
        "C": "rgba(249,115,22,0.12)",
        "D": "rgba(239,68,68,0.12)",
        "F": "rgba(239,68,68,0.12)",
    }.get(grade, "rgba(107,114,128,0.12)")


def _severity_color(severity: str) -> str:
    return {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#6b7280",
    }.get(severity, "#6b7280")


def generate_html_report(score_result: ScoreResult, audit_results: list[dict]) -> str:
    """Generate a premium styled standalone HTML safety report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = score_result.total_score
    grade = html.escape(score_result.grade)
    label = html.escape(score_result.grade_label)
    color = _grade_color(score_result.grade)
    bg = _grade_bg(score_result.grade)

    passed = sum(1 for r in audit_results if r.get("passed", False))
    failed = len(audit_results) - passed

    # Gauge arc
    pct = min(score, 100)
    import math
    circ = 2 * math.pi * 70
    offset = circ - (pct / 100) * circ

    # Scenario rows
    rows = ""
    for r in audit_results:
        is_passed = r.get("passed", False)
        badge_cls = "pass" if is_passed else "fail"
        badge_txt = "PASS" if is_passed else "FAIL"
        sev = r.get("severity", "").lower()
        sev_cls = "critical" if sev == "critical" else "high" if sev == "high" else "medium"
        row_class = ' class="fail-row"' if not is_passed else ""
        rows += f"""
            <tr{row_class}>
                <td><span class="badge {badge_cls}">{badge_txt}</span></td>
                <td class="mono">{html.escape(str(r.get('id', '')))}</td>
                <td>{html.escape(str(r.get('name', '')))}</td>
                <td>{html.escape(str(r.get('category', '')))}</td>
                <td><span class="badge {sev_cls}">{html.escape(sev.upper())}</span></td>
                <td>{html.escape(str(r.get('expected_decision', '')))}</td>
                <td>{html.escape(str(r.get('actual_decision', '')))}</td>
            </tr>"""

    # Deductions section
    deduction_section = ""
    if score_result.deductions:
        deduction_rows = ""
        for d in score_result.deductions:
            deduction_rows += f"""
                <tr>
                    <td>{html.escape(str(d.get('scenario', '')))}</td>
                    <td>{html.escape(str(d.get('category', '')))}</td>
                    <td>{html.escape(str(d.get('severity', '')))}</td>
                    <td class="mono">-{d.get('points', 0)}</td>
                    <td>{html.escape(str(d.get('reason', 'Scenario failed')))}</td>
                </tr>"""
        deduction_section = f"""
        <div class="card">
            <h2>⚠️ Deductions</h2>
            <table>
                <thead><tr><th>Scenario</th><th>Category</th><th>Severity</th><th>Points</th><th>Reason</th></tr></thead>
                <tbody>{deduction_rows}</tbody>
            </table>
        </div>"""

    # Category coverage
    cat_rows = ""
    for cat, stats in score_result.category_coverage.items():
        f_count = stats.get("failed", 0)
        row_cls = ' class="fail-row"' if f_count > 0 else ""
        p_count = stats.get("passed", 0)
        t_count = stats.get("total", 0)
        pct_bar = (p_count / t_count * 100) if t_count else 0
        bar_color = color if pct_bar == 100 else "#f97316" if pct_bar >= 50 else "#ef4444"
        cat_rows += f"""
            <tr{row_cls}>
                <td>{html.escape(str(cat))}</td>
                <td>{t_count}</td>
                <td>{p_count}</td>
                <td>{f_count}</td>
                <td>
                    <div class="bar-bg"><div class="bar-fill" style="width:{pct_bar:.0f}%;background:{bar_color}"></div></div>
                </td>
            </tr>"""

    # Recommendations
    rec_items = ""
    for rec in score_result.recommendations:
        rec_items += f"<li>{html.escape(str(rec))}</li>\n"

    return f"""<!DOCTYPE html>
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
.gauge-fill{{fill:none;stroke:{color};stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1s ease}}
.gauge-text{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}}
.gauge-value{{font-size:2rem;font-weight:800;color:{color}}}
.gauge-label{{color:#94a3b8;font-size:0.85rem;margin-top:-2px}}
.stat-card{{background:#111827;border-radius:16px;padding:24px;text-align:center;border:1px solid rgba(255,255,255,0.06)}}
.stat-card .value{{font-size:2rem;font-weight:800}}
.stat-card .label{{color:#94a3b8;font-size:0.85rem;margin-top:4px}}
.stat-card.pass .value{{color:#10b981}}
.stat-card.fail .value{{color:#ef4444}}
.stat-card.total .value{{color:#a78bfa}}
.grade-pill{{display:inline-block;background:{bg};color:{color};padding:6px 20px;border-radius:99px;font-weight:700;font-size:1.1rem;margin-top:12px;border:1px solid {color}33}}
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
.bar-bg{{display:inline-block;width:120px;height:12px;background:#1e293b;border-radius:6px;vertical-align:middle}}
.bar-fill{{height:100%;border-radius:6px}}
ul{{padding-left:20px}}
li{{margin-bottom:8px;color:#cbd5e1}}
.footer{{text-align:center;color:#475569;font-size:0.8rem;margin-top:48px;padding-top:24px;border-top:1px solid #1e293b}}
@media print{{body{{background:#fff;color:#111}}
.card,.score-card,.stat-card{{background:#f8fafc;border-color:#e2e8f0}}
.header h1{{-webkit-text-fill-color:#111;background:none}}
thead th{{color:#475569}}
tbody td{{border-color:#e2e8f0}}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <div class="brand"><span>🛡️</span> ButterFence Pro</div>
    <h1>Security Safety Report</h1>
    <p class="subtitle">Generated {now} &middot; v{__version__}</p>
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
        <div class="grade-pill">Grade {grade} &mdash; {label}</div>
    </div>
    <div style="display:flex;flex-direction:column;gap:16px;justify-content:center">
        <div class="stat-card total"><div class="value">{len(audit_results)}</div><div class="label">Total Scenarios</div></div>
        <div class="stat-card pass"><div class="value">{passed}</div><div class="label">Passed</div></div>
        <div class="stat-card fail"><div class="value">{failed}</div><div class="label">Failed</div></div>
    </div>
</div>

<div class="card">
    <h2>📋 Scenario Results</h2>
    <table>
        <thead><tr><th>Status</th><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Expected</th><th>Actual</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>

{deduction_section}

<div class="card">
    <h2>📊 Category Coverage</h2>
    <table>
        <thead><tr><th>Category</th><th>Total</th><th>Passed</th><th>Failed</th><th>Coverage</th></tr></thead>
        <tbody>{cat_rows}</tbody>
    </table>
</div>

<div class="card">
    <h2>💡 Recommendations</h2>
    <ul>{rec_items}</ul>
</div>

<div class="footer">
    ButterFence Pro v{__version__} &mdash; Claude Code Safety Harness<br>
    Report generated {now}
</div>

</div>
</body>
</html>"""
