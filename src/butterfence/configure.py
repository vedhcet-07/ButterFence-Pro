"""Interactive config wizard — `butterfence configure`."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from butterfence.config import load_config, save_config, validate_config

console = Console()


def run_configure(project_dir: Path) -> None:
    """Interactive configuration wizard."""
    config = load_config(project_dir)

    console.print(Panel("[bold]ButterFence Configuration Wizard[/bold]", style="blue"))

    while True:
        console.print("\n[bold]Menu:[/bold]")
        console.print("  1. Enable/disable categories")
        console.print("  2. Set category severity")
        console.print("  3. Set category action")
        console.print("  4. Add custom pattern")
        console.print("  5. Add safe-list pattern")
        console.print("  6. Set entropy threshold")
        console.print("  7. Show current config summary")
        console.print("  8. Save and exit")
        console.print("  9. Exit without saving")

        choice = Prompt.ask("Choose", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"])

        categories = config.get("categories", {})
        cat_names = list(categories.keys())

        if choice == "1":
            _toggle_categories(categories, cat_names)
        elif choice == "2":
            _set_severity(categories, cat_names)
        elif choice == "3":
            _set_action(categories, cat_names)
        elif choice == "4":
            _add_pattern(categories, cat_names)
        elif choice == "5":
            _add_safe_pattern(categories, cat_names)
        elif choice == "6":
            threshold = Prompt.ask("Entropy threshold", default=str(config.get("entropy_threshold", 4.5)))
            try:
                config["entropy_threshold"] = float(threshold)
                console.print(f"  [green]Set to {config['entropy_threshold']}[/green]")
            except ValueError:
                console.print("  [red]Invalid number[/red]")
        elif choice == "7":
            _show_summary(config)
        elif choice == "8":
            errors = validate_config(config)
            if errors:
                for e in errors:
                    console.print(f"  [red]{e}[/red]")
            else:
                save_config(config, project_dir)
                console.print("[green]Config saved![/green]")
            break
        elif choice == "9":
            console.print("[yellow]Exiting without saving.[/yellow]")
            break


def _toggle_categories(categories: dict, cat_names: list[str]) -> None:
    for i, name in enumerate(cat_names, 1):
        enabled = categories[name].get("enabled", True)
        status = "[green]ON[/green]" if enabled else "[red]OFF[/red]"
        console.print(f"  {i}. {name}: {status}")
    idx = Prompt.ask("Toggle category number", default="0")
    try:
        cat = cat_names[int(idx) - 1]
        categories[cat]["enabled"] = not categories[cat].get("enabled", True)
        console.print(f"  [cyan]{cat}[/cyan] → {'enabled' if categories[cat]['enabled'] else 'disabled'}")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection[/red]")


def _set_severity(categories: dict, cat_names: list[str]) -> None:
    for i, name in enumerate(cat_names, 1):
        console.print(f"  {i}. {name}: {categories[name].get('severity', 'high')}")
    idx = Prompt.ask("Category number", default="0")
    try:
        cat = cat_names[int(idx) - 1]
        sev = Prompt.ask("Severity", choices=["critical", "high", "medium", "low"])
        categories[cat]["severity"] = sev
        console.print(f"  [cyan]{cat}[/cyan] → {sev}")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection[/red]")


def _set_action(categories: dict, cat_names: list[str]) -> None:
    for i, name in enumerate(cat_names, 1):
        console.print(f"  {i}. {name}: {categories[name].get('action', 'block')}")
    idx = Prompt.ask("Category number", default="0")
    try:
        cat = cat_names[int(idx) - 1]
        action = Prompt.ask("Action", choices=["block", "warn", "allow"])
        categories[cat]["action"] = action
        console.print(f"  [cyan]{cat}[/cyan] → {action}")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection[/red]")


def _add_pattern(categories: dict, cat_names: list[str]) -> None:
    for i, name in enumerate(cat_names, 1):
        console.print(f"  {i}. {name}")
    idx = Prompt.ask("Category number", default="0")
    try:
        cat = cat_names[int(idx) - 1]
        pattern = Prompt.ask("Regex pattern")
        categories[cat].setdefault("patterns", []).append(pattern)
        console.print(f"  [green]Added to {cat}[/green]")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection[/red]")


def _add_safe_pattern(categories: dict, cat_names: list[str]) -> None:
    for i, name in enumerate(cat_names, 1):
        console.print(f"  {i}. {name}")
    idx = Prompt.ask("Category number", default="0")
    try:
        cat = cat_names[int(idx) - 1]
        pattern = Prompt.ask("Safe-list regex pattern")
        categories[cat].setdefault("safe_list", []).append(pattern)
        console.print(f"  [green]Added safe-list to {cat}[/green]")
    except (ValueError, IndexError):
        console.print("  [red]Invalid selection[/red]")


def _show_summary(config: dict) -> None:
    categories = config.get("categories", {})
    console.print(f"\n  Version: {config.get('version', 1)}")
    console.print(f"  Entropy threshold: {config.get('entropy_threshold', 4.5)}")
    console.print(f"  Installed packs: {config.get('installed_packs', [])}")
    console.print(f"  Categories ({len(categories)}):")
    for name, cat in categories.items():
        enabled = "[green]ON[/green]" if cat.get("enabled", True) else "[red]OFF[/red]"
        console.print(
            f"    {name}: {enabled} | {cat.get('severity','high')} | "
            f"{cat.get('action','block')} | {len(cat.get('patterns',[]))} patterns"
        )
