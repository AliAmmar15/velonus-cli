"""pr command group — trigger an on-demand security review of a GitHub PR.

Requires ``velonus auth login`` and a linked GitHub App installation (see
the dashboard's Settings → Integrations page, or POST /v1/github/installations
from the /github/callback flow).

Usage::

    velonus pr review https://github.com/acme/webapp/pull/42
"""

from __future__ import annotations

import re

import typer
from rich.console import Console

from shield.core.api_client import APIConnectionError, APIError, client_from_config

app = typer.Typer()
console = Console(legacy_windows=False)

_PR_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)/?$"
)


@app.command("review")
def review(
    pr_url: str = typer.Argument(
        ..., help="Full GitHub PR URL, e.g. https://github.com/owner/repo/pull/42"
    ),
) -> None:
    """Trigger a Velonus security review of a GitHub pull request.

    Scans the PR's changed files, posts inline review comments and a check
    run to GitHub, and prints a findings summary here.
    """
    match = _PR_URL_RE.match(pr_url.strip())
    if not match:
        console.print(
            "[red]✗[/red] Not a valid GitHub PR URL. "
            "Expected: [cyan]https://github.com/owner/repo/pull/123[/cyan]"
        )
        raise typer.Exit(code=1)

    owner = match.group("owner")
    repo = match.group("repo")
    pr_number = int(match.group("number"))

    client = client_from_config()
    if client is None:
        console.print(
            "[yellow]⚠ Not authenticated.[/yellow] Run [cyan]velonus auth login[/cyan] first."
        )
        raise typer.Exit(code=1)

    console.print(f"Reviewing [cyan]{owner}/{repo}#{pr_number}[/cyan] ...")

    try:
        result = client.review_pr(owner, repo, pr_number)
    except APIConnectionError:
        console.print("[red]✗[/red] Cannot reach the Velonus API — check your connection.")
        raise typer.Exit(code=1) from None
    except APIError as exc:
        console.print(f"[red]✗[/red] {exc.message}")
        raise typer.Exit(code=1) from None

    status = result.get("status")
    if status == "skipped":
        console.print(f"[yellow]⚠ Review skipped:[/yellow] {result.get('reason')}")
        raise typer.Exit(code=1)

    finding_count = result.get("finding_count", 0)
    critical = result.get("critical_count", 0)
    high = result.get("high_count", 0)
    conclusion = result.get("conclusion", "unknown")

    console.print()
    if finding_count:
        console.print(
            f"[bold]{finding_count}[/bold] finding(s) posted as inline review comments "
            f"([red]{critical} critical[/red], [orange3]{high} high[/orange3])."
        )
    else:
        console.print("[green]✓ No findings — clean scan.[/green]")
    console.print(f"Check run conclusion: [bold]{conclusion}[/bold]")

    if conclusion == "failure":
        raise typer.Exit(code=1)
