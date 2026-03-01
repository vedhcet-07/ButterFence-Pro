"""Typer CLI: init, audit, report, status + new commands."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from butterfence import __version__

BANNER = r"""
[bold yellow]
 ____        _   _            _____
| __ ) _   _| |_| |_ ___ _ _|  ___|__ _ __   ___ ___
|  _ \| | | | __| __/ _ \ '__| |_ / _ \ '_ \ / __/ _ \
| |_) | |_| | |_| ||  __/ |  |  _|  __/ | | | (_|  __/
|____/ \__,_|\__|\__\___|_|  |_|  \___|_| |_|\___\___|
[/bold yellow]
[dim]Claude Code Safety Harness v{version}[/dim]
"""

app = typer.Typer(
    name="butterfence",
    help="Claude Code safety harness - red-team and protect your repos.",
)
pack_app = typer.Typer(help="Manage community rule packs.")
app.add_typer(pack_app, name="pack")
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(BANNER.format(version=__version__))
        raise typer.Exit()


def _validate_project_dir(project_dir: Path) -> None:
    """Validate that the project directory exists and is accessible."""
    if not project_dir.exists():
        console.print(f"[red]Error:[/red] Directory not found: {project_dir}")
        raise typer.Exit(1)
    if not project_dir.is_dir():
        console.print(f"[red]Error:[/red] Not a directory: {project_dir}")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version.", callback=_version_callback, is_eager=True
    ),
) -> None:
    """ButterFence - Claude Code safety harness."""
    if ctx.invoked_subcommand is None and not version:
        console.print(BANNER.format(version=__version__))
        console.print("[bold]Quickstart:[/bold]")
        console.print("  butterfence init          Install safety hooks")
        console.print("  butterfence audit         Run 44 red-team scenarios")
        console.print("  butterfence redteam       AI red-team with Opus 4.6")
        console.print("")
        console.print("Run [bold]butterfence --help[/bold] for all 14 commands.\n")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
    no_hooks: bool = typer.Option(False, "--no-hooks", help="Skip hook installation"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Initialize ButterFence in the current project."""
    _validate_project_dir(project_dir)
    from butterfence.config import DEFAULT_CONFIG, load_config, save_config, validate_config
    from butterfence.installer import install_hooks
    from butterfence.utils import deep_merge, load_json

    console.print(BANNER.format(version=__version__))

    bf_dir = project_dir / ".butterfence"
    (bf_dir / "logs").mkdir(parents=True, exist_ok=True)
    (bf_dir / "reports").mkdir(parents=True, exist_ok=True)

    config_path = bf_dir / "config.json"
    if config_path.exists() and not force:
        existing = load_json(config_path)
        config = deep_merge(DEFAULT_CONFIG, existing)
        console.print("  [yellow]Merged with existing config[/yellow]")
    else:
        config = DEFAULT_CONFIG.copy()
        console.print("  [green]Created default config[/green]")

    errors = validate_config(config)
    if errors:
        for e in errors:
            console.print(f"  [red]Config error: {e}[/red]")
        raise typer.Exit(1)

    save_config(config, project_dir)
    console.print(f"  Config: [cyan]{config_path}[/cyan]")

    if not no_hooks:
        settings_path = install_hooks(project_dir)
        console.print(f"  Hooks: [cyan]{settings_path}[/cyan]")
    else:
        console.print("  Hooks: [yellow]skipped[/yellow]")

    cat_count = len(config.get("categories", {}))
    pattern_count = sum(
        len(c.get("patterns", [])) for c in config.get("categories", {}).values()
    )
    console.print("")
    console.print(
        Panel(
            f"[green]ButterFence initialized![/green]\n"
            f"  Categories: {cat_count}\n"
            f"  Patterns: {pattern_count}\n"
            f"  Hooks: {'installed' if not no_hooks else 'skipped'}\n\n"
            f"Next: run [bold]butterfence audit[/bold] to test your defenses.",
            title="Ready",
            style="green",
        )
    )


@app.command()
def audit(
    quick: bool = typer.Option(False, "--quick", help="Critical scenarios only"),
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    scenario: str = typer.Option(None, "--scenario", "-s", help="Run specific scenario"),
    report_flag: bool = typer.Option(False, "--report", "-r", help="Generate report after audit"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed match info"),
    cvss: bool = typer.Option(False, "--cvss", help="Use CVSS v3.1 scoring instead of legacy"),
    edge_mode: bool = typer.Option(False, "--edge-mode", help="Use ONNX edge classifier (zero cloud calls)"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Run red-team audit scenarios against current configuration."""
    _validate_project_dir(project_dir)
    from butterfence.audit import run_audit
    from butterfence.config import load_config
    from butterfence.report import generate_report
    from butterfence.scoring import calculate_score

    console.print(BANNER.format(version=__version__))

    config = load_config(project_dir)

    with console.status("[bold blue]Running scenarios...[/bold blue]"):
        results = run_audit(
            config=config,
            category_filter=category,
            scenario_filter=scenario,
            quick=quick,
        )

    table = Table(title="Audit Results", expand=True)
    table.add_column("", style="bold", width=4, no_wrap=True)
    table.add_column("ID", no_wrap=True, ratio=2)
    table.add_column("Name", ratio=4)
    table.add_column("Category", no_wrap=True, ratio=3)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Result", no_wrap=True, width=7)

    passed = 0
    failed = 0
    for r in results:
        if r.passed:
            passed += 1
            status = "[green]OK[/green]"
        else:
            failed += 1
            status = "[red]FAIL[/red]"

        sev_colors = {"critical": "red bold", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_short = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
        sev_s = sev_short.get(r.severity, r.severity)
        sev_c = sev_colors.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_c}]{sev_s}[/{sev_c}]" if sev_c else sev_s,
            r.actual_decision,
        )

        if verbose and r.match_result.matches:
            for m in r.match_result.matches:
                console.print(f"    [dim]  matched: {m.pattern}[/dim]")

    console.print(table)
    console.print(
        f"\n[bold]Results:[/bold] [green]{passed} passed[/green], "
        f"[red]{failed} failed[/red] / {len(results)} total"
    )

    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in results
    ]

    score = calculate_score(audit_dicts, config)

    score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
    console.print(
        f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
        f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
    )

    if cvss:
        from butterfence.scoring import calculate_cvss_score
        cvss_score = calculate_cvss_score(audit_dicts, config)
        if cvss_score.cvss_details:
            cvss_table = Table(title="CVSS v3.1 Details (Failed Scenarios)", expand=True)
            cvss_table.add_column("Scenario", ratio=2)
            cvss_table.add_column("Category", ratio=2)
            cvss_table.add_column("CVSS Score", width=10, no_wrap=True)
            cvss_table.add_column("Severity", width=10, no_wrap=True)
            cvss_table.add_column("Vector", ratio=4)
            for d in cvss_score.cvss_details:
                sev_colors = {"Critical": "red bold", "High": "yellow", "Medium": "blue", "Low": "dim", "None": "dim"}
                sev_c = sev_colors.get(d["cvss_severity"], "")
                cvss_table.add_row(
                    d["scenario"],
                    d["category"],
                    f"[bold]{d['cvss_score']}[/bold]",
                    f"[{sev_c}]{d['cvss_severity']}[/{sev_c}]" if sev_c else d["cvss_severity"],
                    f"[dim]{d['cvss_vector']}[/dim]",
                )
            console.print(cvss_table)
            console.print(
                f"\n[bold]CVSS Summary:[/bold] Max: [red]{cvss_score.max_cvss}[/red] | "
                f"Avg: [yellow]{cvss_score.avg_cvss}[/yellow]"
            )
        else:
            console.print("\n[green]No CVSS findings — all scenarios passed![/green]")

    if report_flag:
        report_path = project_dir / ".butterfence" / "reports" / "latest_report.md"
        generate_report(score, audit_dicts, report_path)
        console.print(f"\n[green]Report saved to:[/green] {report_path}")


@app.command()
def report(
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|html|json|sarif|junit"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    cvss: bool = typer.Option(False, "--cvss", help="Include CVSS v3.1 scoring in report"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Generate a safety report from the latest audit."""
    _validate_project_dir(project_dir)
    from butterfence.audit import run_audit
    from butterfence.config import load_config
    from butterfence.report import generate_report
    from butterfence.scoring import calculate_score

    console.print(Panel("[bold]ButterFence Report[/bold]", style="blue"))

    config = load_config(project_dir)

    with console.status("[bold blue]Running full audit...[/bold blue]"):
        results = run_audit(config=config)

    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in results
    ]

    score = calculate_score(audit_dicts, config)

    if fmt == "html":
        from butterfence.exporters.html_report import generate_html_report
        report_text = generate_html_report(score, audit_dicts)
        default_ext = "html"
    elif fmt == "json":
        import json
        from butterfence.exporters.json_export import audit_to_json
        report_text = json.dumps(audit_to_json(score, audit_dicts), indent=2)
        default_ext = "json"
    elif fmt == "sarif":
        import json
        from butterfence.exporters.sarif import audit_to_sarif
        report_text = json.dumps(audit_to_sarif(audit_dicts, config), indent=2)
        default_ext = "sarif"
    elif fmt == "junit":
        from butterfence.exporters.junit import audit_to_junit
        report_text = audit_to_junit(audit_dicts)
        default_ext = "xml"
    else:
        report_path = output or (project_dir / ".butterfence" / "reports" / "latest_report.md")
        generate_report(score, audit_dicts, report_path)
        score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
        console.print(
            f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
            f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
        )
        if cvss:
            from butterfence.scoring import calculate_cvss_score
            cvss_result = calculate_cvss_score(audit_dicts, config)
            if cvss_result.cvss_details:
                # Append CVSS section to the report file
                cvss_lines = ["\n---\n", "## CVSS v3.1 Details\n"]
                cvss_lines.append("| Scenario | Category | CVSS | Severity | Vector |")
                cvss_lines.append("|----------|----------|------|----------|--------|")
                for d in cvss_result.cvss_details:
                    cvss_lines.append(
                        f"| {d['scenario']} | {d['category']} | {d['cvss_score']} | "
                        f"{d['cvss_severity']} | {d['cvss_vector']} |"
                    )
                cvss_lines.append(f"\n**Max CVSS:** {cvss_result.max_cvss} | **Avg CVSS:** {cvss_result.avg_cvss}\n")
                with open(report_path, "a", encoding="utf-8") as f:
                    f.write("\n".join(cvss_lines))
                console.print("[green]CVSS v3.1 details appended to report[/green]")
        console.print(f"[green]Report saved to:[/green] {report_path}")
        return

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report saved to:[/green] {output}")
    else:
        default_path = project_dir / ".butterfence" / "reports" / f"latest_report.{default_ext}"
        default_path.parent.mkdir(parents=True, exist_ok=True)
        default_path.write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report saved to:[/green] {default_path}")


@app.command()
def status(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Show current ButterFence status."""
    _validate_project_dir(project_dir)
    from butterfence.config import load_config, validate_config
    from butterfence.installer import BUTTERFENCE_MARKER
    from butterfence.utils import load_json

    console.print(Panel("[bold]ButterFence Status[/bold]", style="blue"))

    bf_dir = project_dir / ".butterfence"
    config_path = bf_dir / "config.json"
    settings_path = project_dir / ".claude" / "settings.local.json"
    log_path = bf_dir / "logs" / "events.jsonl"

    if config_path.exists():
        config = load_config(project_dir)
        errors = validate_config(config)
        cat_count = len(config.get("categories", {}))
        pattern_count = sum(
            len(c.get("patterns", [])) for c in config.get("categories", {}).values()
        )
        if errors:
            console.print(f"  Config: [red]invalid ({len(errors)} errors)[/red]")
        else:
            console.print(f"  Config: [green]valid[/green] ({cat_count} categories, {pattern_count} patterns)")
    else:
        console.print("  Config: [red]not found[/red] (run `butterfence init`)")

    if settings_path.exists():
        settings = load_json(settings_path)
        hook_count = 0
        for event in ("PreToolUse", "PostToolUse"):
            for hook_group in settings.get("hooks", {}).get(event, []):
                for hook in hook_group.get("hooks", []):
                    if BUTTERFENCE_MARKER in hook.get("command", ""):
                        hook_count += 1
        if hook_count > 0:
            console.print(f"  Hooks: [green]installed[/green] ({hook_count} hook entries)")
        else:
            console.print("  Hooks: [yellow]not installed[/yellow]")
    else:
        console.print("  Hooks: [red]no settings file[/red]")

    if log_path.exists():
        line_count = sum(1 for _ in open(log_path, encoding="utf-8"))
        console.print(f"  Events: [cyan]{line_count} logged[/cyan]")
    else:
        console.print("  Events: [dim]none[/dim]")

    report_path = bf_dir / "reports" / "latest_report.md"
    if report_path.exists():
        console.print(f"  Report: [cyan]{report_path}[/cyan]")
    else:
        console.print("  Report: [dim]none generated yet[/dim]")


@app.command()
def watch(
    refresh: float = typer.Option(0.5, "--refresh", help="Refresh interval in seconds"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Live monitoring dashboard for ButterFence events."""
    _validate_project_dir(project_dir)
    from butterfence.watcher import run_watcher

    run_watcher(project_dir, refresh=refresh)


@app.command()
def scan(
    fix: bool = typer.Option(False, "--fix", help="Show remediation suggestions"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|json|sarif"),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", help="Entropy detection threshold"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Scan repository for secrets and security issues."""
    _validate_project_dir(project_dir)
    import json

    from butterfence.scanner import scan_repo

    console.print(Panel("[bold]ButterFence Repo Scanner[/bold]", style="blue"))

    with console.status("[bold blue]Scanning repository...[/bold blue]"):
        result = scan_repo(project_dir, entropy_threshold=entropy_threshold, fix=fix)

    console.print(
        f"\n  Files scanned: [cyan]{result.files_scanned}[/cyan], "
        f"skipped: [dim]{result.files_skipped}[/dim], "
        f"findings: [{'red' if result.findings else 'green'}]{len(result.findings)}[/{'red' if result.findings else 'green'}]"
    )

    if fmt == "json":
        data = {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "rule": f.rule,
                    "severity": f.severity,
                    "matched_text": f.matched_text,
                    "suggestion": f.suggestion,
                }
                for f in result.findings
            ],
        }
        out = json.dumps(data, indent=2)
        if output:
            output.write_text(out, encoding="utf-8")
            console.print(f"[green]Output saved to:[/green] {output}")
        else:
            console.print(out)
        return

    if fmt == "sarif":
        from butterfence.exporters.sarif import audit_to_sarif

        audit_dicts = [
            {
                "id": f"scan-{i}",
                "name": f.rule,
                "category": "scanner",
                "severity": f.severity,
                "passed": False,
                "expected_decision": "block",
                "actual_decision": "allow",
                "reason": f"{f.file}:{f.line} - {f.matched_text}",
            }
            for i, f in enumerate(result.findings, 1)
        ]
        out = json.dumps(audit_to_sarif(audit_dicts), indent=2)
        if output:
            output.write_text(out, encoding="utf-8")
            console.print(f"[green]Output saved to:[/green] {output}")
        else:
            console.print(out)
        return

    # Default: table
    if not result.findings:
        console.print("\n[green]No security issues found![/green]")
        return

    table = Table(title="Scan Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("File", width=30)
    table.add_column("Line", width=6)
    table.add_column("Rule", width=25)
    table.add_column("Match", width=40)

    for f in result.findings:
        sev_style = {
            "critical": "red bold",
            "high": "yellow",
            "medium": "blue",
            "low": "dim",
        }.get(f.severity, "")
        table.add_row(
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.file,
            str(f.line),
            f.rule,
            f.matched_text[:40],
        )

    console.print(table)

    if fix:
        console.print("\n[bold]Remediation Suggestions:[/bold]")
        seen: set[str] = set()
        for f in result.findings:
            if f.suggestion and f.suggestion not in seen:
                seen.add(f.suggestion)
                console.print(f"  - {f.suggestion}")


@app.command(name="supply-chain")
def supply_chain_cmd(
    fix: bool = typer.Option(False, "--fix", "-f", help="Show safe alternatives for suspicious packages"),
    fmt: str = typer.Option("table", "--format", help="Output format: table|json|sarif"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
) -> None:
    """Scan dependency files for typosquatting and malicious packages."""
    _validate_project_dir(project_dir)
    import json as json_mod

    from butterfence.supply_chain import scan_supply_chain

    console.print(BANNER.format(version=__version__))
    console.print(
        Panel(
            "[bold cyan]Supply Chain Scanner[/bold cyan]\n"
            "Checking dependencies for typosquatting and malicious packages",
            style="cyan",
        )
    )

    with console.status(
        "[bold cyan]Scanning dependency files...[/bold cyan]",
        spinner="dots",
    ):
        result = scan_supply_chain(project_dir)

    console.print(f"\n[bold]Files scanned:[/bold] {result.files_scanned}")
    console.print(f"[bold]Packages checked:[/bold] {result.packages_checked}")

    if result.total_issues == 0:
        console.print("\n[bold green]No supply chain issues found![/bold green]")
        return

    # JSON / SARIF output
    if fmt in ("json", "sarif"):
        findings_data = [
            {
                "package": f.package,
                "source_file": f.source_file,
                "severity": f.severity,
                "reason": f.reason,
                "safe_alternative": f.safe_alternative,
                "line_number": f.line_number,
            }
            for f in result.findings
        ]
        out = json_mod.dumps({
            "files_scanned": result.files_scanned,
            "packages_checked": result.packages_checked,
            "total_issues": result.total_issues,
            "typosquats_found": result.typosquats_found,
            "malicious_found": result.malicious_found,
            "findings": findings_data,
        }, indent=2)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(out, encoding="utf-8")
            console.print(f"[green]Output saved to:[/green] {output}")
        else:
            console.print(out)
        return

    # Table output
    table = Table(title="Supply Chain Findings", show_lines=True, expand=True)
    table.add_column("Sev", width=8, no_wrap=True)
    table.add_column("Package", ratio=2)
    table.add_column("File", ratio=2)
    table.add_column("Reason", ratio=3)
    if fix:
        table.add_column("Safe Alternative", ratio=2)

    for f in result.findings:
        sev_style = {
            "critical": "red bold",
            "high": "yellow",
            "medium": "blue",
            "low": "dim",
        }.get(f.severity, "")
        sev_short = {
            "critical": "CRIT",
            "high": "HIGH",
            "medium": "MED",
            "low": "LOW",
        }.get(f.severity, f.severity)

        row = [
            f"[{sev_style}]{sev_short}[/{sev_style}]",
            f.package,
            f.source_file,
            f.reason,
        ]
        if fix:
            row.append(f.safe_alternative or "[dim]—[/dim]")

        table.add_row(*row)

    console.print(table)

    # Summary
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[red]{result.malicious_found} malicious[/red], "
        f"[yellow]{result.typosquats_found} typosquats[/yellow] / "
        f"{result.total_issues} total issues"
    )

    if not fix and result.total_issues > 0:
        console.print(
            "\n[dim]Tip: run with --fix to see safe alternatives[/dim]"
        )


@app.command()
def ci(
    min_score: int = typer.Option(80, "--min-score", help="Minimum passing score"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json|sarif|junit"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    badge: Path = typer.Option(None, "--badge", help="Generate SVG badge file"),
    generate_workflow: bool = typer.Option(False, "--generate-workflow", help="Generate GitHub Actions workflow"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Run audit in CI mode with pass/fail exit codes."""
    _validate_project_dir(project_dir)
    from butterfence.ci import generate_github_workflow, run_ci

    if generate_workflow:
        workflow_path = project_dir / ".github" / "workflows" / "butterfence.yml"
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(generate_github_workflow(), encoding="utf-8")
        console.print(f"[green]Workflow written to:[/green] {workflow_path}")
        return

    passed, info = run_ci(
        project_dir=project_dir,
        min_score=min_score,
        output_format=fmt,
        output_file=output,
        badge_file=badge,
    )

    score_color = "green" if passed else "red"
    console.print(
        f"Score: [{score_color}]{info['score']}/{info['max_score']}[/{score_color}] "
        f"({info['grade']}) | Min: {min_score}"
    )
    console.print(
        f"Scenarios: {info['scenarios_passed']} passed, "
        f"{info['scenarios_failed']} failed / {info['scenarios_total']} total"
    )

    if output:
        console.print(f"Output: {output}")
    if badge:
        console.print(f"Badge: {badge}")

    if passed:
        console.print("[green]CI PASSED[/green]")
    else:
        console.print("[red]CI FAILED[/red]")
        raise typer.Exit(1)


def _persist_redteam_to_db(
    project_dir: Path,
    result: "RedTeamResult",
    score_total: int = 0,
    score_grade: str = "",
) -> int | None:
    """Save red team results to the SQLite database.

    Inserts a scan record plus one threat row per scenario.
    Returns the scan_id on success, or None if DB write fails.
    """
    try:
        from butterfence.database import get_connection, insert_scan, insert_threat

        with get_connection(project_dir) as conn:
            # 1. Save the overall scan record
            scan_id = insert_scan(
                conn,
                scan_type="redteam",
                total_scenarios=result.scenarios_run,
                passed=result.caught,
                failed=result.missed,
                score=result.catch_rate,
                grade=score_grade or (
                    "A" if result.catch_rate >= 90
                    else "B" if result.catch_rate >= 70
                    else "C" if result.catch_rate >= 50
                    else "D"
                ),
                model_used=result.model_used,
                details={
                    "score_total": score_total,
                    "raw_scenarios": result.raw_scenarios,
                    "results": [
                        {"id": r.id, "name": r.name, "category": r.category,
                         "severity": r.severity, "passed": r.passed,
                         "actual_decision": r.actual_decision}
                        for r in result.results
                    ],
                },
            )

            # 2. Save each scenario as a threat record
            for scenario in result.raw_scenarios:
                r_match = next(
                    (r for r in result.results if r.id == scenario.get("id")),
                    None,
                )
                decision = "block" if (r_match and r_match.passed) else "allow"
                insert_threat(
                    conn,
                    hook_event="RedTeam",
                    tool_name=scenario.get("tool", "unknown"),
                    tool_input=scenario.get("tool_input", {}),
                    decision=decision,
                    reason=scenario.get("name", ""),
                    category=scenario.get("category", ""),
                    severity=scenario.get("severity", ""),
                    match_count=1 if decision == "block" else 0,
                )

        return scan_id
    except Exception as exc:
        logger.warning("Failed to save red team results to database: %s", exc)
        return None


def _run_verify_mode(
    console: Console,
    project_dir: Path,
    config: dict,
    count: int,
    model: str,
    cat_list: list[str] | None,
    verbose: bool,
    save: bool,
    report_flag: bool,
) -> None:
    """Execute the full attack-fix-verify loop and display results.

    Extracted as a helper so the main redteam command stays readable.
    """
    import json as json_mod

    from butterfence.config import get_config_path, load_config
    from butterfence.redteam import (
        APICallError,
        APIKeyMissingError,
        RedTeamError,
        ScenarioParseError,
        run_redteam_with_verify,
    )
    from butterfence.scoring import calculate_score

    config_path = get_config_path(project_dir)

    # Detect provider key in model param (e.g. "gemini", "claude")
    from butterfence.models import AVAILABLE_MODELS as _AVAIL
    use_multi = model.lower() in _AVAIL
    provider_label = model.lower() if use_multi else model

    try:
        # Step 1: Initial attack
        with console.status(
            f"[bold red]{provider_label} is thinking like an attacker...[/bold red]",
            spinner="dots",
        ):
            if use_multi:
                from butterfence.redteam import run_multi_model_redteam
                initial_result = run_multi_model_redteam(
                    config=config,
                    target_dir=project_dir,
                    models=[model.lower()],
                    count=count,
                    categories=cat_list,
                )
            else:
                from butterfence.redteam import run_redteam
                initial_result = run_redteam(
                    config=config,
                    target_dir=project_dir,
                    count=count,
                    model=model,
                    categories=cat_list,
                )
    except APIKeyMissingError as exc:
        console.print(f"\n[red]API Key Error:[/red] {exc}")
        console.print("\n[dim]Setup: butterfence auth / butterfence auth-gemini  |  Or: export ANTHROPIC_API_KEY / GOOGLE_API_KEY[/dim]")
        raise typer.Exit(1)
    except APICallError as exc:
        console.print(f"\n[red]API Error:[/red] {exc}")
        raise typer.Exit(1)
    except ScenarioParseError as exc:
        console.print(f"\n[red]Parse Error:[/red] {exc}")
        raise typer.Exit(1)
    except RedTeamError as exc:
        console.print(f"\n[red]Red Team Error:[/red] {exc}")
        raise typer.Exit(1)

    # --- Panel 1: Initial Run ---
    _show_result_table(console, initial_result, "Initial Red Team Results", verbose)
    initial_rate = initial_result.catch_rate

    console.print(
        Panel(
            f"[bold]{initial_result.caught}/{initial_result.scenarios_run} caught[/bold] "
            f"({initial_rate:.0f}% catch rate)",
            title="Initial Run",
            border_style="red" if initial_result.missed > 0 else "green",
        )
    )

    # Persist initial results to database
    scan_id = _persist_redteam_to_db(project_dir, initial_result)
    if scan_id:
        console.print(f"[dim]Initial results saved to database (scan #{scan_id})[/dim]")

    missed = [r for r in initial_result.results if not r.passed]

    if not missed:
        console.print(
            Panel(
                "[bold green]All scenarios caught on first run![/bold green]\n"
                "No fixes needed -- your defenses are solid.",
                title="Verification Complete",
                border_style="green",
            )
        )
        return

    # --- Step 2: Generate fixes ---
    from butterfence.redteam import (
        apply_fixes,
        generate_fix_suggestions,
        generate_fix_suggestions_multi,
        _rerun_scenarios_with_config,
    )

    try:
        with console.status(
            f"[bold yellow]{provider_label} is analyzing gaps and generating fixes...[/bold yellow]",
            spinner="dots",
        ):
            if use_multi:
                suggestions = generate_fix_suggestions_multi(
                    missed, config, model_key=model.lower(),
                    raw_scenarios=initial_result.raw_scenarios,
                )
            else:
                suggestions = generate_fix_suggestions(
                    missed, config, model=model,
                    raw_scenarios=initial_result.raw_scenarios,
                )
    except (APICallError, RedTeamError) as exc:
        console.print(f"[yellow]Fix generation failed:[/yellow] {exc}")
        return

    if not suggestions:
        console.print("[yellow]No fix suggestions could be generated.[/yellow]")
        return

    # --- Panel 2: Fix Suggestions ---
    fix_table = Table(title="AI-Suggested Fixes", show_lines=True)
    fix_table.add_column("Category", width=20)
    fix_table.add_column("New Patterns", ratio=1)
    fix_table.add_column("Explanation", ratio=1)

    for s in suggestions:
        patterns_str = chr(10).join(s.new_patterns)
        fix_table.add_row(s.category, patterns_str, s.explanation)

    console.print(fix_table)

    # --- Step 3: Apply fixes ---
    patterns_added = apply_fixes(suggestions, config, config_path)

    # Save patches to database
    try:
        from butterfence.database import get_connection, insert_patch
        with get_connection(project_dir) as conn:
            for s in suggestions:
                insert_patch(
                    conn,
                    category=s.category,
                    patterns_added=s.new_patterns,
                    explanation=s.explanation,
                    source_scan_id=scan_id,
                )
    except Exception:
        pass  # Don't fail the main flow if DB write fails

    console.print(
        Panel(
            f"[bold green]{patterns_added} new pattern(s) added[/bold green] to config",
            title="AI Fix Applied",
            border_style="yellow",
        )
    )

    if patterns_added == 0:
        console.print("[dim]No new patterns to verify.[/dim]")
        return

    # --- Step 4: Re-run same scenarios against patched config ---
    with console.status(
        "[bold blue]Re-running scenarios against patched config...[/bold blue]",
        spinner="dots",
    ):
        updated_config = load_config(config_path.parent.parent)
        verify_result = _rerun_scenarios_with_config(
            raw_scenarios=initial_result.raw_scenarios,
            config=updated_config,
            model_used=initial_result.model_used,
            repo_context=initial_result.repo_context,
        )

    # --- Panel 3: Verification Results ---
    _show_result_table(console, verify_result, "Verification Results", verbose)

    verify_rate = verify_result.catch_rate
    improvement = int(verify_rate - initial_rate)

    console.print(
        Panel(
            f"[bold]{verify_result.caught}/{verify_result.scenarios_run} caught[/bold] "
            f"({verify_rate:.0f}% catch rate)",
            title="Verification Run",
            border_style="green" if verify_result.missed == 0 else "yellow",
        )
    )

    # --- Improvement Summary ---
    if improvement > 0:
        color = "green"
        sign = "+"
    elif improvement == 0:
        color = "yellow"
        sign = ""
    else:
        color = "red"
        sign = ""

    console.print(
        f"\n[bold {color}]Improvement: {initial_rate:.0f}% -> {verify_rate:.0f}% "
        f"({sign}{improvement}% improvement)[/bold {color}]"
    )

    if verify_result.missed == 0:
        console.print("[bold green]All attacks now caught after patching![/bold green]")
    elif verify_result.missed < initial_result.missed:
        still_missed = verify_result.missed
        console.print(
            f"[yellow]{still_missed} scenario(s) still missed. "
            f"Run --verify again to iterate.[/yellow]"
        )

    # Save results if requested
    if save:
        save_path = project_dir / ".butterfence" / "verify_results.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_data = {
            "initial_catch_rate": initial_rate,
            "verify_catch_rate": verify_rate,
            "improvement": improvement,
            "patterns_added": patterns_added,
            "initial_caught": initial_result.caught,
            "initial_missed": initial_result.missed,
            "verify_caught": verify_result.caught,
            "verify_missed": verify_result.missed,
            "scenarios_total": initial_result.scenarios_run,
        }
        save_path.write_text(json_mod.dumps(save_data, indent=2), encoding="utf-8")
        console.print(f"\n[green]Verify results saved to:[/green] {save_path}")


def _show_result_table(
    console: Console,
    result: "RedTeamResult",
    title: str,
    verbose: bool,
) -> None:
    """Display a red-team results table (shared by initial and verify runs)."""
    table = Table(title=title, expand=True)
    table.add_column("", style="bold", width=6, no_wrap=True)
    table.add_column("ID", no_wrap=True, ratio=2)
    table.add_column("Name", ratio=4)
    table.add_column("Category", no_wrap=True, ratio=3)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Result", no_wrap=True, width=7)

    for r in result.results:
        status = "[green]CAUGHT[/green]" if r.passed else "[red]MISSED[/red]"
        sev_colors = {"critical": "red bold", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_short = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
        sev_s = sev_short.get(r.severity, r.severity)
        sev_c = sev_colors.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_c}]{sev_s}[/{sev_c}]" if sev_c else sev_s,
            r.actual_decision,
        )

        if verbose and r.match_result.matches:
            for m in r.match_result.matches:
                console.print(f"    [dim]  matched: {m.pattern}[/dim]")

    console.print(table)


@app.command()
def redteam(
    count: int = typer.Option(10, "--count", "-n", help="Number of scenarios to generate"),
    model: str = typer.Option("claude-opus-4-6", "--model", "-m", help="Model provider (claude, gemini) or full model name"),
    models: str = typer.Option(None, "--models", help="Comma-separated model providers: claude,gemini"),
    categories: str = typer.Option(None, "--categories", "-c", help="Comma-separated categories"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to JSON"),
    report_flag: bool = typer.Option(False, "--report", "-r", help="Generate report after"),
    fix: bool = typer.Option(False, "--fix", "-f", help="Auto-fix gaps with AI-suggested patterns"),
    verify: bool = typer.Option(False, "--verify", help="Full loop: attack, fix gaps, verify improvement"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed match info"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
) -> None:
    """AI red-team: use Claude/Gemini to generate novel attack scenarios."""
    _validate_project_dir(project_dir)
    import json as json_mod

    from butterfence.config import get_config_path, load_config
    from butterfence.redteam import (
        APICallError,
        APIKeyMissingError,
        FixSuggestion,
        RedTeamError,
        ScenarioParseError,
        VerifyResult,
        apply_fixes,
        generate_fix_suggestions,
        run_redteam,
        run_redteam_with_verify,
    )
    from butterfence.scoring import calculate_score

    console.print(BANNER.format(version=__version__))

    # Parse --models flag or detect provider key in --model
    from butterfence.models import AVAILABLE_MODELS as _AVAIL
    model_list = None
    if models:
        model_list = [m.strip() for m in models.split(",") if m.strip()]
    elif model.lower() in _AVAIL:
        # --model gemini / --model claude → auto-route via multi-model pipeline
        model_list = [model.lower()]

    if model_list:
        console.print(
            Panel(
                "[bold red]AI Red Team Mode[/bold red]\n"
                f"Using model(s): {', '.join(model_list)}",
                style="red",
            )
        )
    else:
        console.print(
            Panel(
                "[bold red]AI Red Team Mode[/bold red]\n"
                f"Using {model} as adversary to generate novel attacks",
                style="red",
            )
        )

    config = load_config(project_dir)

    cat_list = None
    if categories:
        cat_list = [c.strip() for c in categories.split(",")]

    # --verify implies --fix (verify includes the fix step)
    if verify:
        _run_verify_mode(
            console=console,
            project_dir=project_dir,
            config=config,
            count=count,
            model=model,
            cat_list=cat_list,
            verbose=verbose,
            save=save,
            report_flag=report_flag,
        )
        return

    try:
        if model_list and len(model_list) > 0:
            # Multi-model mode
            from butterfence.redteam import run_multi_model_redteam
            with console.status(
                f"[bold red]Multi-model red team ({', '.join(model_list)}) generating attacks...[/bold red]",
                spinner="dots",
            ):
                result = run_multi_model_redteam(
                    config=config,
                    target_dir=project_dir,
                    models=model_list,
                    count=count,
                    categories=cat_list,
                )
        else:
            # Single model mode (legacy)
            with console.status(
                "[bold red]Opus 4.6 is thinking like an attacker...[/bold red]",
                spinner="dots",
            ):
                result = run_redteam(
                    config=config,
                    target_dir=project_dir,
                    count=count,
                    model=model,
                    categories=cat_list,
                )
    except APIKeyMissingError as exc:
        console.print(f"\n[red]API Key Error:[/red] {exc}")
        console.print("\n[dim]Setup: butterfence auth / butterfence auth-gemini  |  Or: export ANTHROPIC_API_KEY / GOOGLE_API_KEY[/dim]")
        raise typer.Exit(1)
    except APICallError as exc:
        console.print(f"\n[red]API Error:[/red] {exc}")
        raise typer.Exit(1)
    except ScenarioParseError as exc:
        console.print(f"\n[red]Parse Error:[/red] {exc}")
        raise typer.Exit(1)
    except RedTeamError as exc:
        console.print(f"\n[red]Red Team Error:[/red] {exc}")
        console.print("\n[dim]Install: pip install anthropic / google-generativeai  |  Or: pip install butterfence[redteam][/dim]")
        raise typer.Exit(1)

    # Display repo context
    ctx = result.repo_context
    console.print(f"\n[bold]Repo Context:[/bold]")
    console.print(f"  Tech stack: {', '.join(ctx.tech_stack) or 'Unknown'}")
    console.print(f"  Languages: {', '.join(ctx.languages) or 'Unknown'}")
    console.print(f"  Files scanned: {ctx.total_files}")
    console.print(f"  Sensitive files: {len(ctx.sensitive_files)}")
    console.print(f"  Model: {result.model_used}")
    console.print(f"  Scenarios generated: {result.scenarios_generated}")

    # Results table
    table = Table(title="Red Team Results", expand=True)
    table.add_column("", style="bold", width=6, no_wrap=True)
    table.add_column("ID", no_wrap=True, ratio=2)
    table.add_column("Name", ratio=4)
    table.add_column("Category", no_wrap=True, ratio=3)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Result", no_wrap=True, width=7)

    for r in result.results:
        status = "[green]CAUGHT[/green]" if r.passed else "[red]MISSED[/red]"
        sev_colors = {"critical": "red bold", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_short = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
        sev_s = sev_short.get(r.severity, r.severity)
        sev_c = sev_colors.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_c}]{sev_s}[/{sev_c}]" if sev_c else sev_s,
            r.actual_decision,
        )

        if verbose and r.match_result.matches:
            for m in r.match_result.matches:
                console.print(f"    [dim]  matched: {m.pattern}[/dim]")

    console.print(table)

    console.print(
        f"\n[bold]Red Team Summary:[/bold] "
        f"[green]{result.caught} caught[/green], "
        f"[red]{result.missed} missed[/red] / {result.scenarios_run} total "
        f"({result.catch_rate:.0f}% catch rate)"
    )

    # Score
    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in result.results
    ]

    score = calculate_score(audit_dicts, config)
    score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
    console.print(
        f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
        f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
    )

    # Persist to database for dashboard visibility
    scan_id = _persist_redteam_to_db(
        project_dir, result,
        score_total=score.total_score,
        score_grade=score.grade,
    )
    if scan_id:
        console.print(f"[dim]Results saved to database (scan #{scan_id})[/dim]")

    # Fix suggestions
    missed = [r for r in result.results if not r.passed]
    if missed and fix:
        try:
            with console.status(
                "[bold yellow]Analyzing gaps and generating fixes...[/bold yellow]",
                spinner="dots",
            ):
                if model_list:
                    from butterfence.redteam import generate_fix_suggestions_multi
                    suggestions = generate_fix_suggestions_multi(
                        missed, config, model_key=model_list[0],
                        raw_scenarios=result.raw_scenarios,
                    )
                else:
                    suggestions = generate_fix_suggestions(missed, config, model=model, raw_scenarios=result.raw_scenarios)

            if suggestions:
                fix_table = Table(title="Suggested Fixes", show_lines=True)
                fix_table.add_column("Category", width=20)
                fix_table.add_column("New Patterns", ratio=1)
                fix_table.add_column("Explanation", ratio=1)

                for s in suggestions:
                    patterns_str = chr(10).join(s.new_patterns)
                    fix_table.add_row(s.category, patterns_str, s.explanation)

                console.print(fix_table)

                config_path = get_config_path(project_dir)
                added = apply_fixes(suggestions, config, config_path)
                console.print(
                    f"[green]Applied {added} new pattern(s).[/green] "
                    "Re-run [bold]butterfence redteam[/bold] to verify."
                )

                # Save patches to database
                if scan_id:
                    try:
                        from butterfence.database import get_connection, insert_patch
                        with get_connection(project_dir) as conn:
                            for s in suggestions:
                                insert_patch(
                                    conn,
                                    category=s.category,
                                    patterns_added=s.new_patterns,
                                    explanation=s.explanation,
                                    source_scan_id=scan_id,
                                )
                    except Exception:
                        pass
            else:
                console.print("[yellow]No fix suggestions could be generated.[/yellow]")
        except (APICallError, RedTeamError) as exc:
            console.print(f"[yellow]Fix generation failed:[/yellow] {exc}")
    elif missed and not fix:
        console.print(
            "[dim]Tip: run with --fix to auto-generate patterns for missed attacks[/dim]"
        )

    # Save results
    if save:
        save_path = project_dir / ".butterfence" / "redteam_results.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_data = {
            "model": result.model_used,
            "scenarios_generated": result.scenarios_generated,
            "caught": result.caught,
            "missed": result.missed,
            "catch_rate": result.catch_rate,
            "score": {
                "total": score.total_score,
                "max": score.max_score,
                "grade": score.grade,
                "label": score.grade_label,
            },
            "repo_context": {
                "root": ctx.root,
                "tech_stack": ctx.tech_stack,
                "languages": ctx.languages,
                "total_files": ctx.total_files,
                "sensitive_files_count": len(ctx.sensitive_files),
            },
            "scenarios": result.raw_scenarios,
            "results": audit_dicts,
        }
        save_path.write_text(json_mod.dumps(save_data, indent=2), encoding="utf-8")
        console.print(f"\n[green]Results saved to:[/green] {save_path}")

    # Generate report
    if report_flag:
        from butterfence.report import generate_report

        report_path = project_dir / ".butterfence" / "reports" / "redteam_report.md"
        generate_report(score, audit_dicts, report_path)
        console.print(f"[green]Report saved to:[/green] {report_path}")


@app.command()
def analytics(
    period: str = typer.Option("all", "--period", "-p", help="Time period: 1h|24h|7d|30d|all"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Show analytics from event log."""
    _validate_project_dir(project_dir)
    from butterfence.analytics import analyze_events

    console.print(Panel("[bold]ButterFence Analytics[/bold]", style="blue"))

    result = analyze_events(project_dir, period=period)

    if result.total_events == 0:
        console.print("\n[dim]No events found. Run some hook events first.[/dim]")
        return

    console.print(f"\n  Total events: [cyan]{result.total_events}[/cyan]")
    console.print(f"  [red]Blocks:[/red] {result.blocks}  [yellow]Warns:[/yellow] {result.warns}  [green]Allows:[/green] {result.allows}")
    console.print(f"  Block rate: {result.block_rate:.1f}%")
    console.print(f"  Threat trend: {result.threat_trend}")

    if result.by_tool:
        console.print("\n[bold]By Tool:[/bold]")
        for tool, count in result.by_tool.most_common():
            console.print(f"  {tool}: {count}")

    if result.by_category:
        console.print("\n[bold]By Category:[/bold]")
        for cat, count in result.by_category.most_common():
            bar = "\u2588" * min(count, 30)
            console.print(f"  {cat:<20} {bar} {count}")

    if result.blocked_patterns:
        console.print("\n[bold]Most Blocked:[/bold]")
        for pat, count in result.blocked_patterns.most_common(10):
            console.print(f"  {pat}: {count}")


@app.command()
def explain(
    scenario_id: str = typer.Argument(..., help="Scenario ID to explain (e.g. shell-001)"),
) -> None:
    """Show educational explanation for a threat scenario."""
    from butterfence.explainer import get_all_scenario_ids, load_explanation

    info = load_explanation(scenario_id)

    if not info:
        all_ids = get_all_scenario_ids()
        console.print(f"[red]Scenario '{scenario_id}' not found.[/red]")
        if all_ids:
            console.print(f"Available: {', '.join(all_ids[:20])}")
        raise typer.Exit(1)

    expl = info.get("explanation", {})
    sev_style = {
        "critical": "red bold",
        "high": "yellow",
        "medium": "blue",
        "low": "dim",
    }.get(info.get("severity", ""), "")

    lines = [
        f"[bold]{info['name']}[/bold] ({info['id']})",
        f"Category: {info['category']}",
        f"Severity: [{sev_style}]{info['severity']}[/{sev_style}]" if sev_style else f"Severity: {info['severity']}",
        "",
    ]

    if expl.get("what"):
        lines.append(f"[bold]What it does:[/bold] {expl['what']}")
    if expl.get("why_dangerous"):
        lines.append(f"[bold]Why dangerous:[/bold] {expl['why_dangerous']}")
    if expl.get("real_world"):
        lines.append(f"[bold]Real-world example:[/bold] {expl['real_world']}")
    if expl.get("safe_alternative"):
        lines.append(f"[bold]Safe alternative:[/bold] {expl['safe_alternative']}")

    if not expl:
        lines.append("[dim]No detailed explanation available for this scenario.[/dim]")

    console.print(Panel("\n".join(lines), title="Threat Explanation", border_style="yellow"))


@app.command()
def auth(
    key: str = typer.Option(None, "--key", "-k", help="API key to save"),
    status_flag: bool = typer.Option(False, "--status", "-s", help="Show current key status"),
    remove: bool = typer.Option(False, "--remove", help="Remove stored key"),
) -> None:
    """Manage Anthropic API key for AI red-team features."""
    from butterfence.auth import (
        check_key_permissions,
        get_key_path,
        load_key,
        mask_key,
        remove_key,
        save_key,
        validate_key_format,
    )

    key_path = get_key_path()

    # --- Remove ---
    if remove:
        removed = remove_key()
        if removed:
            console.print("[green]API key securely removed.[/green]")
        else:
            console.print("[dim]No stored key found.[/dim]")
        return

    # --- Status ---
    if status_flag:
        console.print(Panel("[bold]API Key Status[/bold]", style="blue"))

        # Check env var
        env_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if env_key:
            console.print(f"  Env var: [green]set[/green] [green]OK[/green] ({mask_key(env_key)})")
        else:
            console.print("  Env var: [dim]not set[/dim] [dim]--[/dim]")

        # Check stored key
        stored = load_key()
        if stored:
            console.print(f"  Stored:  [green]saved[/green] [green]OK[/green] ({mask_key(stored)})")
            console.print(f"  Path:    [cyan]{key_path}[/cyan]")
            warnings = check_key_permissions(key_path)
            if warnings:
                for w in warnings:
                    console.print(f"  [yellow]Warning: {w}[/yellow]")
            else:
                console.print("  Perms:   [green]secure[/green]")
        else:
            console.print("  Stored:  [dim]none[/dim] [dim]--[/dim]")

        # Overall
        if env_key or stored:
            console.print("\n  [green]Ready for butterfence redteam[/green]")
        else:
            console.print("\n  [yellow]No key configured. Run: butterfence auth[/yellow]")
        return

    # --- Save (interactive or via --key) ---
    if key:
        api_key = key
    else:
        # Interactive prompt with hidden input
        import getpass

        console.print(
            Panel(
                "[bold]API Key Setup[/bold]\n\n"
                "Get your key at: [cyan]https://console.anthropic.com/settings/keys[/cyan]\n"
                "The key will be stored securely at:\n"
                f"  [cyan]{key_path}[/cyan]\n"
                "with owner-only permissions.",
                style="blue",
            )
        )
        api_key = getpass.getpass("Enter your Anthropic API key: ")

    if not api_key or not api_key.strip():
        console.print("[red]No key provided.[/red]")
        raise typer.Exit(1)

    if not validate_key_format(api_key.strip()):
        console.print("[red]Invalid key format.[/red] Keys must start with 'sk-' and be 20+ characters.")
        raise typer.Exit(1)

    try:
        saved_path = save_key(api_key)
        console.print(f"\n[green]API key saved securely![/green]")
        console.print(f"  Key:  {mask_key(api_key.strip())}")
        console.print(f"  Path: [cyan]{saved_path}[/cyan]")
        console.print(f"  Perms: owner-only read/write")
        console.print(f"\n  Run [bold]butterfence redteam[/bold] to start AI red-teaming.")
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@app.command(name="auth-gemini")
def auth_gemini(
    key: str = typer.Option(None, "--key", "-k", help="Gemini API key to save"),
    status_flag: bool = typer.Option(False, "--status", "-s", help="Show Gemini key status"),
) -> None:
    """Manage Google Gemini API key for multi-model red-teaming."""
    from butterfence.auth import (
        get_gemini_key_path,
        load_gemini_key,
        mask_key,
        save_gemini_key,
    )

    key_path = get_gemini_key_path()

    if status_flag:
        console.print(Panel("[bold]Gemini API Key Status[/bold]", style="blue"))

        for env_var in ("GOOGLE_API_KEY", "GEMINI_API_KEY"):
            val = os.environ.get(env_var, "").strip()
            if val:
                console.print(f"  {env_var}: [green]set[/green] ({mask_key(val)})")
            else:
                console.print(f"  {env_var}: [dim]not set[/dim]")

        stored = load_gemini_key()
        if stored:
            console.print(f"  Stored:  [green]saved[/green] ({mask_key(stored)})")
            console.print(f"  Path:    [cyan]{key_path}[/cyan]")
        else:
            console.print("  Stored:  [dim]none[/dim]")

        if any(os.environ.get(v, "").strip() for v in ("GOOGLE_API_KEY", "GEMINI_API_KEY")) or stored:
            console.print("\n  [green]Ready for multi-model redteam[/green]")
        else:
            console.print("\n  [yellow]No Gemini key. Run: butterfence auth-gemini[/yellow]")
        return

    # Save
    if key:
        api_key = key
    else:
        import getpass
        console.print(
            Panel(
                "[bold]Gemini API Key Setup[/bold]\n\n"
                "Get your key at: [cyan]https://aistudio.google.dev/apikey[/cyan]\n"
                f"Stored at: [cyan]{key_path}[/cyan]",
                style="blue",
            )
        )
        api_key = getpass.getpass("Enter your Gemini API key: ")

    if not api_key or not api_key.strip():
        console.print("[red]No key provided.[/red]")
        raise typer.Exit(1)

    try:
        saved_path = save_gemini_key(api_key)
        console.print(f"\n[green]Gemini API key saved![/green]")
        console.print(f"  Key:  {mask_key(api_key.strip())}")
        console.print(f"  Path: [cyan]{saved_path}[/cyan]")
        console.print(f"\n  Run [bold]butterfence redteam --models gemini[/bold] to use.")
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@app.command()
def policy(
    check: bool = typer.Option(False, "--check", help="Evaluate policies against audit scenarios"),
    add: str = typer.Option(None, "--add", help="Add a new policy"),
    list_flag: bool = typer.Option(False, "--list", "-l", help="List current policies"),
    remove: int = typer.Option(None, "--remove", help="Remove policy by index"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
) -> None:
    """Manage and evaluate natural language security policies (Opus 4.6)."""
    _validate_project_dir(project_dir)
    from butterfence.config import load_config, save_config

    config = load_config(project_dir)
    policies = config.get("policies", [])

    # --- List ---
    if list_flag:
        if not policies:
            console.print("[dim]No policies defined. Add one with: butterfence policy --add \"...\"[/dim]")
            return
        console.print(Panel("[bold]Security Policies[/bold]", style="blue"))
        for i, p in enumerate(policies):
            console.print(f"  [{i}] {p}")
        return

    # --- Add ---
    if add:
        policies.append(add)
        config["policies"] = policies
        save_config(config, project_dir)
        console.print(f"[green]Policy added:[/green] {add}")
        console.print(f"  Total policies: {len(policies)}")
        return

    # --- Remove ---
    if remove is not None:
        if 0 <= remove < len(policies):
            removed = policies.pop(remove)
            config["policies"] = policies
            save_config(config, project_dir)
            console.print(f"[yellow]Policy removed:[/yellow] {removed}")
        else:
            console.print(f"[red]Invalid index {remove}. Range: 0-{len(policies) - 1}[/red]")
            raise typer.Exit(1)
        return

    # --- Check (evaluate with Opus 4.6) ---
    if check:
        if not policies:
            console.print("[red]No policies to check.[/red] Add one first:")
            console.print("  butterfence policy --add \"Never modify production files\"")
            raise typer.Exit(1)

        from butterfence.audit import load_scenarios
        from butterfence.policy import PolicyEvalError, evaluate_policies

        scenarios = load_scenarios()
        if not scenarios:
            console.print("[red]No scenarios loaded.[/red]")
            raise typer.Exit(1)

        console.print(Panel(
            "[bold magenta]Policy Evaluation[/bold magenta]\n"
            "Using Claude Opus 4.6 to evaluate natural language policies",
            style="magenta",
        ))
        console.print(f"  Policies: {len(policies)}")
        console.print(f"  Scenarios: {len(scenarios)}")

        try:
            with console.status("[bold magenta]Opus 4.6 is evaluating policies...[/bold magenta]", spinner="dots"):
                result = evaluate_policies(policies, scenarios)
        except PolicyEvalError as exc:
            console.print(f"\n[red]Policy Error:[/red] {exc}")
            raise typer.Exit(1)
        except Exception as exc:
            console.print(f"\n[red]Error:[/red] {exc}")
            raise typer.Exit(1)

        # Display results
        table = Table(title="Policy Evaluation Results", expand=True)
        table.add_column("Policy", ratio=4)
        table.add_column("Violations", width=10, justify="right")
        table.add_column("Status", width=12, no_wrap=True)

        for pr in result.results:
            v_count = len(pr.violations)
            if v_count == 0:
                status = "[green]COMPLIANT[/green]"
            else:
                status = f"[red]{v_count} VIOLATED[/red]"

            table.add_row(pr.policy, str(v_count), status)

        console.print(table)

        # Show violation details
        for pr in result.results:
            if pr.violations:
                console.print(f"\n[bold red]Violations for:[/bold red] {pr.policy}")
                if pr.reasoning:
                    console.print(f"  [dim]{pr.reasoning}[/dim]")
                for v in pr.violations:
                    console.print(f"  - {v.get('id', '?')}: {v.get('name', '?')} ({v.get('category', '?')})")

        console.print(
            f"\n[bold]Summary:[/bold] {result.policies_checked} policies, "
            f"{result.total_violations} total violations"
        )
        return

    # Default: show help
    console.print("Usage:")
    console.print("  butterfence policy --list              List policies")
    console.print("  butterfence policy --add \"...\"          Add a policy")
    console.print("  butterfence policy --remove N           Remove by index")
    console.print("  butterfence policy --check              Evaluate with Opus 4.6")


@app.command()
def configure(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Interactive configuration wizard."""
    _validate_project_dir(project_dir)
    from butterfence.configure import run_configure

    run_configure(project_dir)


@app.command()
def uninstall(
    remove_data: bool = typer.Option(False, "--remove-data", help="Also remove .butterfence/ directory"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Remove ButterFence hooks and optionally all data."""
    _validate_project_dir(project_dir)
    import shutil

    from butterfence.installer import uninstall_hooks

    console.print(Panel("[bold]ButterFence Uninstall[/bold]", style="red"))

    result = uninstall_hooks(project_dir)
    if result:
        console.print(f"  Hooks removed from: [cyan]{result}[/cyan]")
    else:
        console.print("  [dim]No hooks found to remove[/dim]")

    if remove_data:
        bf_dir = project_dir / ".butterfence"
        if bf_dir.exists():
            shutil.rmtree(bf_dir)
            console.print(f"  [red]Removed:[/red] {bf_dir}")
        else:
            console.print("  [dim]No .butterfence/ directory found[/dim]")

    console.print("[green]ButterFence uninstalled.[/green]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
    reload_flag: bool = typer.Option(False, "--reload", help="Auto-reload on changes"),
) -> None:
    """Start the ButterFence REST API server."""
    _validate_project_dir(project_dir)

    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]uvicorn is required for the API server.[/red]\n"
            "Install with: [bold]pip install butterfence[api][/bold]"
        )
        raise typer.Exit(1)

    try:
        from butterfence.api import create_app
    except ImportError as exc:
        console.print(f"[red]API dependencies missing:[/red] {exc}")
        console.print("Install with: [bold]pip install butterfence[api][/bold]")
        raise typer.Exit(1)

    console.print(BANNER.format(version=__version__))
    console.print(
        Panel(
            f"[bold green]ButterFence API Server[/bold green]\n"
            f"Listening on: [cyan]http://{host}:{port}[/cyan]\n"
            f"Swagger docs: [cyan]http://{host}:{port}/docs[/cyan]\n"
            f"Project dir:  [cyan]{project_dir}[/cyan]",
            style="green",
        )
    )

    # Create the app with the project directory
    api_app = create_app(project_dir)

    uvicorn.run(
        api_app,
        host=host,
        port=port,
        log_level="info",
    )


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't auto-open browser"),
) -> None:
    """Launch the ButterFence web dashboard."""
    _validate_project_dir(project_dir)

    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]uvicorn is required.[/red]\n"
            "Install with: [bold]pip install butterfence[api][/bold]"
        )
        raise typer.Exit(1)

    try:
        from butterfence.api import create_app
    except ImportError as exc:
        console.print(f"[red]API dependencies missing:[/red] {exc}")
        raise typer.Exit(1)

    dashboard_url = f"http://{host}:{port}/dashboard"

    console.print(BANNER.format(version=__version__))
    console.print(
        Panel(
            f"[bold cyan]ButterFence Dashboard[/bold cyan]\n"
            f"Dashboard: [bold green]{dashboard_url}[/bold green]\n"
            f"API docs:  [cyan]http://{host}:{port}/docs[/cyan]\n"
            f"Project:   [cyan]{project_dir}[/cyan]",
            style="cyan",
        )
    )

    # Auto-open browser
    if not no_browser:
        import threading
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open(dashboard_url)).start()

    api_app = create_app(project_dir)

    uvicorn.run(
        api_app,
        host=host,
        port=port,
        log_level="info",
    )


@app.command(name="edge-export")
def edge_export(
    output: Path = typer.Option(None, "--output", "-o", help="Output path for .onnx model"),
    quantize: bool = typer.Option(False, "--quantize", help="Also generate INT8 quantized model"),
) -> None:
    """Export/train the ONNX threat classifier model for edge mode."""
    console.print(BANNER.format(version=__version__))

    try:
        from butterfence.edge.model_export import export_onnx_model, quantize_model
    except ImportError as exc:
        console.print(f"[red]Missing dependencies:[/red] {exc}")
        console.print("Install with: [bold]pip install butterfence[edge][/bold]")
        raise typer.Exit(1)

    console.print(Panel("[bold cyan]Edge Model Export[/bold cyan]", style="cyan"))

    with console.status("[bold cyan]Training classifier...[/bold cyan]"):
        model_path = export_onnx_model(output_path=output)

    console.print(f"[green]ONNX model exported:[/green] {model_path}")
    console.print(f"  Size: {model_path.stat().st_size / 1024:.1f} KB")

    if quantize:
        with console.status("[bold cyan]Quantizing to INT8...[/bold cyan]"):
            q_path = quantize_model(model_path)
        console.print(f"[green]Quantized model:[/green] {q_path}")
        console.print(f"  Size: {q_path.stat().st_size / 1024:.1f} KB")

    console.print("\n[bold green]Done![/bold green] Use [bold]--edge-mode[/bold] flag with audit/serve.")


@app.command(name="edge-info")
def edge_info() -> None:
    """Show edge runtime information (providers, model, NPU status)."""
    console.print(BANNER.format(version=__version__))
    console.print(Panel("[bold cyan]Edge Runtime Info[/bold cyan]", style="cyan"))

    from butterfence.edge import (
        DEFAULT_MODEL_PATH,
        get_available_providers,
        has_amd_npu,
        is_edge_available,
    )

    console.print(f"  ONNX Runtime: {'[green]installed[/green]' if is_edge_available() else '[red]not installed[/red]'}")

    if is_edge_available():
        providers = get_available_providers()
        console.print(f"  Providers: {', '.join(providers)}")
        console.print(f"  AMD NPU: {'[green]available[/green]' if has_amd_npu() else '[yellow]not detected (CPU fallback)[/yellow]'}")
    else:
        console.print("  Install: [bold]pip install butterfence[edge][/bold]")

    if DEFAULT_MODEL_PATH.exists():
        console.print(f"  Model: [green]{DEFAULT_MODEL_PATH}[/green] ({DEFAULT_MODEL_PATH.stat().st_size / 1024:.1f} KB)")
    else:
        console.print("  Model: [yellow]not found[/yellow] — run [bold]butterfence edge-export[/bold]")


# --- Pack sub-commands ---

@pack_app.command("list")
def pack_list(
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """List available rule packs."""
    from butterfence.packs import list_packs

    packs = list_packs(packs_dir)
    if not packs:
        console.print("[dim]No packs found.[/dim]")
        return

    table = Table(title="Available Rule Packs", expand=True)
    table.add_column("Pack", no_wrap=True, style="bold cyan", ratio=1)
    table.add_column("Description", ratio=4)
    table.add_column("Rules", no_wrap=True, width=5, justify="right")

    for p in packs:
        desc = p.description[:70] + "..." if len(p.description) > 70 else p.description
        cat_count = sum(len(c.get("patterns", [])) for c in p.categories.values())
        table.add_row(
            p.name,
            desc,
            str(cat_count),
        )

    console.print(table)


@pack_app.command("install")
def pack_install(
    name: str = typer.Argument(..., help="Pack name to install"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """Install a rule pack into the current config."""
    from butterfence.packs import install_pack

    success = install_pack(name, project_dir, packs_dir)
    if success:
        console.print(f"[green]Pack '{name}' installed successfully![/green]")
    else:
        console.print(f"[red]Pack '{name}' not found.[/red]")
        raise typer.Exit(1)


@pack_app.command("info")
def pack_info(
    name: str = typer.Argument(..., help="Pack name to inspect"),
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """Show details for a rule pack."""
    from butterfence.packs import get_pack_info

    pack = get_pack_info(name, packs_dir)
    if not pack:
        console.print(f"[red]Pack '{name}' not found.[/red]")
        raise typer.Exit(1)

    lines = [
        f"[bold]{pack.name}[/bold] v{pack.version}",
        f"Author: {pack.author}",
        f"Description: {pack.description}",
        "",
        f"[bold]Categories ({len(pack.categories)}):[/bold]",
    ]
    for cat_name, cat_config in pack.categories.items():
        patterns = cat_config.get("patterns", [])
        lines.append(
            f"  {cat_name}: {len(patterns)} patterns | "
            f"{cat_config.get('severity', 'high')} | {cat_config.get('action', 'block')}"
        )

    console.print(Panel("\n".join(lines), title="Pack Info", border_style="cyan"))
