"""auth command group — Clerk-based authentication via API key.

Auth flow (Phase 2):
  1. User creates an API key in the Velonus dashboard.
  2. ``velonus auth login`` prompts for that key and validates connectivity.
  3. The key is stored in ``~/.velonus/config.toml`` under [auth].
  4. All API calls (--ai flag in scan, future dashboard sync) use this key.

This avoids a browser-based Clerk OAuth flow in the terminal, which would
require running a local callback server. Simple is better for Phase 2.
API key rotation and OAuth are Phase 4+ concerns (dashboard must exist first).
"""

from __future__ import annotations

import typer
from rich.console import Console

from shield.core import config as cfg
from shield.core.api_client import APIConnectionError, VelonusClient

app = typer.Typer()
console = Console(legacy_windows=False)

_DASHBOARD_URL = "https://www.velonus.com/dashboard/settings"


@app.command("login")
def login(
    api_url: str = typer.Option(
        cfg.DEFAULT_API_URL,
        "--api-url",
        help="Override the Velonus API base URL (for self-hosted instances).",
        show_default=True,
    ),
    key: str | None = typer.Option(
        None,
        "--key",
        help="API key to save directly (skips interactive prompt).",
    ),
) -> None:
    """Authenticate with the Velonus API using an API key.

    Get your API key from the dashboard:
    [cyan]https://www.velonus.com/dashboard/settings[/cyan]
    """
    console.print()
    console.print("[bold green]Velonus[/bold green] — API authentication\n")

    if key:
        api_key = key.strip()
    else:
        console.print(f"  Get your API key from: [cyan]{_DASHBOARD_URL}[/cyan]\n")
        api_key = typer.prompt("  Paste your API key").strip()

    if not api_key:
        console.print("[red]✗ No API key provided.[/red]")
        raise typer.Exit(code=1)

    # Step 1: confirm the API host is reachable (unauthenticated /health check).
    console.print(f"\n  [dim]Connecting to {api_url} ...[/dim]")
    try:
        client = VelonusClient(api_key=api_key, api_url=api_url)
        reachable = client.health()
    except APIConnectionError as exc:
        console.print(
            f"\n[red]✗ Could not reach the Velonus API:[/red] {exc}\n"
            f"  Check the API URL and your network connection.\n"
            f"  To use a different URL: [dim]velonus auth login --api-url <url>[/dim]"
        )
        raise typer.Exit(code=1) from exc

    if not reachable:
        console.print(
            "\n[red]✗ API returned an unexpected response.[/red]\n  The API URL may be incorrect."
        )
        raise typer.Exit(code=1)

    # Step 2: validate the key against an authenticated endpoint before saving.
    console.print("  [dim]Validating API key ...[/dim]")
    try:
        key_valid = client.validate_key()
    except APIConnectionError as exc:
        console.print(f"\n[red]✗ Could not validate key:[/red] {exc}\n")
        raise typer.Exit(code=1) from exc

    if not key_valid:
        console.print(
            "\n[red]✗ API key is invalid or expired.[/red]\n"
            f"  Get a valid key from: [cyan]{_DASHBOARD_URL}[/cyan]\n"
        )
        raise typer.Exit(code=1)

    # Save credentials.
    cfg.set_credentials(api_key=api_key, api_url=api_url)

    # Show a truncated key so the user knows what was saved.
    truncated = _truncate_key(api_key)
    console.print(
        f"\n[bold green]✓ Logged in.[/bold green]\n"
        f"  API key: [dim]{truncated}[/dim]\n"
        f"  API URL: [cyan]{api_url}[/cyan]\n"
        f"  Config:  [dim]{cfg.CONFIG_PATH}[/dim]\n"
        "\nRun [bold]velonus scan ./ --ai[/bold] to get AI-powered findings.\n"
    )


@app.command("logout")
def logout() -> None:
    """Clear stored Velonus API credentials.

    Removes the [auth] section from ~/.velonus/config.toml.
    All other config settings (scan exclusions, etc.) are preserved.
    """
    if cfg.get_api_key() is None:
        console.print("[yellow]You are not currently logged in.[/yellow]")
        raise typer.Exit(code=0)

    cfg.clear_credentials()
    console.print(
        "[bold green]✓ Logged out.[/bold green] "
        "Your API credentials have been removed.\n"
        "  Run [bold]velonus auth login[/bold] to authenticate again."
    )


@app.command("status")
def status() -> None:
    """Show current Velonus API authentication status."""
    console.print()
    api_key = cfg.get_api_key()

    if api_key is None:
        console.print(
            "[bold]Authentication status:[/bold] [red]Not logged in[/red]\n\n"
            "  Run [bold]velonus auth login[/bold] to authenticate.\n"
            f"  API keys: [cyan]{_DASHBOARD_URL}[/cyan]"
        )
        raise typer.Exit(code=0)

    api_url = cfg.get_api_url()
    truncated = _truncate_key(api_key)

    console.print(
        f"[bold]Authentication status:[/bold] [green]Logged in[/green]\n\n"
        f"  API key: [dim]{truncated}[/dim]\n"
        f"  API URL: [cyan]{api_url}[/cyan]\n"
        f"  Config:  [dim]{cfg.CONFIG_PATH}[/dim]"
    )

    # Quick connectivity check so the user knows if the API is reachable.
    console.print("\n  [dim]Checking connectivity...[/dim]", end="")
    try:
        client = VelonusClient(api_key=api_key, api_url=api_url)
        ok = client.health()
        if ok:
            console.print("\r  [green]✓ API reachable[/green]              ")
        else:
            console.print("\r  [yellow]⚠ API returned unexpected response[/yellow]")
    except APIConnectionError:
        console.print("\r  [red]✗ API unreachable — check your network[/red]")

    console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_key(key: str) -> str:
    """Return a redacted version of an API key for safe display.

    Shows the first 8 characters and masks the rest:
    ``vn_sk_ab`` → ``vn_sk_ab...``
    """
    if len(key) <= 8:
        return "*" * len(key)
    return key[:8] + "•••"
