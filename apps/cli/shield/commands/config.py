"""config command group — display and modify local CLI configuration.

Manages ``~/.velonus/config.toml``. Supports reading and writing arbitrary
key=value pairs within named TOML sections. The most common keys are:

  auth.api_url     — Velonus API base URL (managed by ``velonus auth login``)
  scan.exclude     — additional glob patterns to exclude from scans

Usage::

    velonus config show
    velonus config set scan.exclude "migrations/"
    velonus config set auth.api_url "https://my.selfhosted.velonus.dev"
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from shield.core import config as cfg

app = typer.Typer()
console = Console(legacy_windows=False)


@app.command("show")
def show() -> None:
    """Display all current Velonus CLI configuration."""
    data = cfg.load()

    if not data:
        console.print(
            "[dim]No configuration found.[/dim] "
            f"Config will be created at [cyan]{cfg.CONFIG_PATH}[/cyan] "
            "when you run [bold]velonus auth login[/bold]."
        )
        raise typer.Exit(code=0)

    console.print(f"\n[bold]Velonus config[/bold] — [dim]{cfg.CONFIG_PATH}[/dim]\n")

    for section, values in data.items():
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=None,
            padding=(0, 2),
        )
        table.add_column("Key", style="dim", no_wrap=True)
        table.add_column("Value")

        if not isinstance(values, dict):
            continue

        for key, value in values.items():
            display_value = _redact(section, key, value)
            table.add_row(f"{section}.{key}", display_value)

        console.print(f"  [bold][{section}][/bold]")
        console.print(table)
        console.print()


@app.command("set")
def set_value(
    key: str = typer.Argument(
        help=("Config key in dot notation: section.key (e.g. scan.api_url, auth.api_url)."),
    ),
    value: str = typer.Argument(
        help="Value to assign.",
    ),
) -> None:
    """Set a configuration value in ~/.velonus/config.toml.

    Key format: ``section.key`` — e.g. ``scan.api_url``.

    Examples::

        velonus config set auth.api_url https://myinstance.velonus.dev
        velonus config set scan.exclude "migrations/"
    """
    if "." not in key:
        console.print(
            f"[red]✗ Invalid key format:[/red] [bold]{key}[/bold]\n"
            "  Keys must be in dot notation: [bold]section.key[/bold]\n"
            "  Example: [dim]velonus config set auth.api_url https://...[/dim]"
        )
        raise typer.Exit(code=1)

    section, field = key.split(".", 1)
    cfg.set_value(section, field, value)

    console.print(
        f"[green]✓[/green] Set [bold]{section}.{field}[/bold] = [cyan]{value}[/cyan]\n"
        f"  Saved to [dim]{cfg.CONFIG_PATH}[/dim]"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact(section: str, key: str, value: object) -> str:
    """Redact sensitive values for display.

    API keys are truncated to the first 8 characters.
    """
    if section == "auth" and key == "api_key" and isinstance(value, str) and value:
        return value[:8] + "•••" if len(value) > 8 else "•••"
    if isinstance(value, list):
        return "[" + ", ".join(f'"{v}"' for v in value) + "]"
    return str(value)
