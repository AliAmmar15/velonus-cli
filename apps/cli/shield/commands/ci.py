"""ci command group — generate CI/CD workflow configuration.

Usage::

    velonus ci --generate-workflow
    velonus ci --generate-workflow --output .github/workflows/velonus.yml
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from shield.core.api_client import APIConnectionError, APIError, client_from_config

app = typer.Typer()
console = Console(legacy_windows=False)


@app.callback(invoke_without_command=True)
def ci(
    generate_workflow: bool = typer.Option(
        False,
        "--generate-workflow",
        help="Fetch a ready-to-use CI workflow and write it to disk.",
    ),
    provider: str = typer.Option(
        "github-actions",
        "--provider",
        help="CI provider to generate a workflow for.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination path. Defaults to the provider's conventional location.",
    ),
) -> None:
    """Generate CI/CD configuration for running Velonus scans automatically."""
    if not generate_workflow:
        console.print(
            "Nothing to do — pass [bold]--generate-workflow[/bold] to fetch a CI template."
        )
        raise typer.Exit(code=0)

    client = client_from_config()
    if client is None:
        console.print(
            "[yellow]⚠ Not authenticated.[/yellow] Run [cyan]velonus auth login[/cyan] first."
        )
        raise typer.Exit(code=1)

    try:
        result = client.get_ci_template(provider=provider)
    except APIConnectionError:
        console.print("[red]✗[/red] Cannot reach the Velonus API — check your connection.")
        raise typer.Exit(code=1) from None
    except APIError as exc:
        console.print(f"[red]✗[/red] {exc.message}")
        raise typer.Exit(code=1) from None

    content = str(result.get("content", ""))
    filename = str(result.get("filename", "velonus-ci.yml"))
    dest = output or Path(filename)

    if dest.exists() and not typer.confirm(f"{dest} already exists. Overwrite?", default=False):
        console.print("[yellow]Aborted.[/yellow] No changes made.")
        raise typer.Exit(code=0)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")

    console.print(f"[bold green]✓[/bold green] Wrote CI workflow to [cyan]{dest}[/cyan]")
    console.print(
        "\n[dim]Add a VELONUS_API_KEY repo/org secret before the workflow can authenticate — "
        "get a key from the dashboard's Settings page.[/dim]"
    )
