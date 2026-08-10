"""
Velonus — CLI entry point.

Defines the root Typer application and registers all command groups:
  - scan     : Run static analysis on a local path
  - auth     : Authenticate with the Velonus API (Phase 2)
  - config   : Manage local CLI configuration (Phase 2)
  - pr       : GitHub PR integration utilities (Phase 3)
  - ci       : Generate CI/CD workflow configuration (Phase 7 5I)

Local-only mode is fully supported without an API connection.
"""

from __future__ import annotations

import sys

# Reconfigure stdout/stderr to UTF-8 on Windows before any output happens.
# Without this, Rich's legacy Windows renderer uses the cp1252 codepage which
# cannot encode emoji (🔴🟠🟡🔵⚪). Setting errors="replace" ensures that
# any unencodable characters are replaced with "?" instead of crashing.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import typer

from shield.commands import auth, ci, config, pr, scan

app = typer.Typer(
    name="velonus",
    help="[bold green]Velonus[/bold green] — AI-native AppSec scanner for developers.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# Register command groups
app.add_typer(scan.app, name="scan", help="Run security scans on a local path.")
app.add_typer(auth.app, name="auth", help="Authenticate with the Velonus API.")
app.add_typer(config.app, name="config", help="Manage Velonus CLI configuration.")
app.add_typer(pr.app, name="pr", help="Trigger an on-demand review of a GitHub PR.")
app.add_typer(ci.app, name="ci", help="Generate CI/CD workflow configuration.")


def main() -> None:
    """Invoke the Velonus CLI application."""
    app()


if __name__ == "__main__":
    main()
