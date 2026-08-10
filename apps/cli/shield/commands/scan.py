"""
scan command — core entry point for local security analysis.

Runs the scanner pipeline on a given path and renders findings
to the terminal using Rich.

Phase 1 pipeline (parallel execution):
  Stage 1: SecretsDetector (synchronous — always first)
  Stage 2: BanditRunner + SemgrepRunner + PipAuditRunner + SafetyRunner
           (concurrent via asyncio.to_thread — all four run simultaneously)
  Post:    FindingNormalizer → DeduplicationFilter → severity sort

Usage:
    velonus scan ./myproject
    velonus scan ./myproject --format json
    velonus scan ./myproject --severity high
    velonus scan ./myproject --verbose
"""

from __future__ import annotations

import asyncio
import shutil as _shutil
import subprocess
import sys
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from scanner.pipeline import ALL_DETECTORS, DEFAULT_EXCLUDE_PATTERNS, ScanPipeline

from shield.core import config as cli_config
from shield.core.api_client import APIConnectionError, APIError, client_from_config
from shield.core.output import Severity
from shield.formatters.sarif import to_sarif, write_sarif
from shield.formatters.terminal import render_findings_table

if TYPE_CHECKING:
    from normalizer.models import NormalizedFinding

# allow_interspersed_args=True lets users place options after the path argument:
#   velonus scan ./project --sarif   (instead of requiring: velonus scan --sarif ./project)
# Click groups disable interspersed args by default; we opt back in here.
app = typer.Typer(context_settings={"allow_interspersed_args": True})

# Use actual terminal width when available; cap at 120 for non-TTY (piped /
# redirected) output. Using min() as a cap (not max as a floor) respects
# narrow terminals — 80-column users should not get overflowing output.
_CONSOLE_WIDTH = min(_shutil.get_terminal_size((120, 24)).columns, 120)

# legacy_windows=False: prevent Rich from using the Win32 console API (cp1252).
# Combined with the UTF-8 reconfiguration in main.py, emoji render correctly.
console = Console(legacy_windows=False, width=_CONSOLE_WIDTH)

# Separate stderr console for status/spinner output.
# Used when --format json is active so that progress messages don't
# corrupt the JSON written to stdout by _output_json().
_stderr_console = Console(stderr=True, legacy_windows=False, width=_CONSOLE_WIDTH)


def _tool_on_path(name: str) -> bool:
    """Return True if a binary is findable on PATH."""
    import shutil

    return shutil.which(name) is not None


def _prompted_marker() -> Path:
    """Return the path to the one-time prompt sentinel file.

    After the user has answered the optional-tools prompts (regardless of
    their answers), we write this file so the prompt never fires again.
    Location: ~/.velonus/.prompted_tools
    """
    return Path.home() / ".velonus" / ".prompted_tools"


def _prompt_optional_tools() -> None:
    """Prompt the user to install optional scanner tools on first use.

    Only runs:
      1. When stdin is a TTY (not in CI, not when piping output).
      2. Only ONCE — a sentinel file is written after the first run so
         subsequent scans skip this entirely.

    Prompts per missing tool:
      - semgrep    → pip-installable, offered auto-install
      - trufflehog → Go binary, shows install link only
    """
    if not sys.stdin.isatty():
        # Non-interactive environment (CI, pipe, script) — skip all prompts.
        return

    marker = _prompted_marker()
    if marker.exists():
        # Already asked. Never ask again.
        return

    missing: list[str] = []
    if not _tool_on_path("semgrep"):
        missing.append("semgrep")
    if not _tool_on_path("trufflehog"):
        missing.append("trufflehog")

    if not missing:
        # All optional tools present — write the marker so we never check again.
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        return

    console.print()
    console.print(
        "[bold yellow]Optional tools not installed[/bold yellow] — "
        "installing them improves scan coverage:\n"
    )

    for tool in missing:
        if tool == "semgrep":
            console.print(
                "  [cyan]semgrep[/cyan]  Pattern-based static analysis (~200 MB). "
                "Detects injection, hardcoded secrets, insecure patterns."
            )
        elif tool == "trufflehog":
            console.print(
                "  [cyan]trufflehog[/cyan]  High-accuracy secret scanning (Go binary). "
                "Detects 700+ credential types with verified entropy checks."
            )

    console.print()

    # --- semgrep (pip-installable — can auto-install) ---
    if "semgrep" in missing:
        if typer.confirm("  Install semgrep now? (~200 MB)", default=False):
            console.print("\n  [dim]Running: pip install semgrep ...[/dim]")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "semgrep"],
                capture_output=False,  # stream pip output directly to terminal
            )
            if result.returncode == 0:
                console.print("  [green]✓ semgrep installed.[/green]\n")
            else:
                console.print(
                    "  [red]semgrep install failed.[/red] "
                    "Run manually: [bold]pip install semgrep[/bold]\n"
                )
        else:
            console.print("  Skipped. Install later with: [bold]pip install semgrep[/bold]\n")

    # --- trufflehog (Go binary — cannot pip install, show link) ---
    if "trufflehog" in missing:
        if typer.confirm("  Show trufflehog install instructions?", default=True):
            console.print(
                "\n  [bold]trufflehog install options:[/bold]\n"
                "    macOS/Linux:  [cyan]curl -sSfL https://raw.githubusercontent.com/"
                "trufflesecurity/trufflehog/main/scripts/install.sh | sh[/cyan]\n"
                "    Windows:      Download from [cyan]https://github.com/trufflesecurity/"
                "trufflehog/releases[/cyan]\n"
                "    Homebrew:     [cyan]brew install trufflesecurity/trufflehog/trufflehog[/cyan]\n"
                "\n"
                "  [dim]Until installed, Velonus uses its built-in entropy-based "
                "secret scanner as a fallback.[/dim]\n"
            )
        else:
            console.print(
                "  Skipped. Install later from: "
                "[cyan]https://github.com/trufflesecurity/trufflehog/releases[/cyan]\n"
            )

    # Persist that we've asked — never prompt again regardless of answers.
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()


def _load_config_excludes() -> list[str]:
    """Read exclusion patterns from ~/.velonus/config.toml if it exists.

    Expected TOML structure::

        [scan]
        exclude = ["tests/", "conftest.py", "mydir/"]

    Returns an empty list when the file is missing, malformed, or has no
    ``[scan] exclude`` key.
    """
    import tomllib

    config_path = Path.home() / ".velonus" / "config.toml"
    if not config_path.exists():
        return []
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
        raw = data.get("scan", {}).get("exclude", [])
        if isinstance(raw, list):
            return [str(p) for p in raw]
    except Exception:  # noqa: BLE001 — malformed TOML silently ignored
        pass
    return []


def _load_config_detectors() -> list[str] | None:
    """Read detector selection from ~/.velonus/config.toml if it exists.

    Expected TOML structure::

        [scan]
        detectors = ["bandit", "semgrep"]

    Returns None when the file is missing, malformed, or has no
    ``[scan] detectors`` key — callers treat None as "run all detectors".
    """
    import tomllib

    config_path = Path.home() / ".velonus" / "config.toml"
    if not config_path.exists():
        return None
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
        raw = data.get("scan", {}).get("detectors")
        if isinstance(raw, list) and raw:
            return [str(d) for d in raw]
    except Exception:  # noqa: BLE001 — malformed TOML silently ignored
        pass
    return None


def _read_source_context(file: Path, line_start: int, redacted_snippet: str) -> str:
    """Return up to 40 lines of source code surrounding *line_start*.

    Replaces the flagged line with the already-redacted snippet so secrets
    are never sent to the server in plaintext.

    Returns empty string if the file cannot be read (binary, permission error, etc.).
    """
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, PermissionError):
        return ""

    total = len(lines)
    first = max(0, line_start - 21)  # 20 lines before (0-indexed)
    last = min(total, line_start + 20)  # 20 lines after
    window = lines[first:last]

    # Replace the flagged line (1-indexed → 0-indexed: line_start - 1). Only
    # when the snippet is a single redacted line — bandit's `code` field is
    # itself a multi-line, already-line-numbered blob, and splicing it into
    # one window slot doubles and misnumbers the surrounding lines once this
    # window gets re-numbered below.
    flagged_idx = (line_start - 1) - first
    if redacted_snippet and "\n" not in redacted_snippet and 0 <= flagged_idx < len(window):
        window[flagged_idx] = redacted_snippet

    start_label = first + 1  # human-readable 1-indexed start
    return "\n".join(f"{start_label + i:4d}: {ln}" for i, ln in enumerate(window))


def _run_ai_enrichment(
    findings: list[NormalizedFinding],
    *,
    target: str,
    exclude_patterns: list[str] | None,
) -> None:
    """Submit the scan to the Velonus API for AI-powered enrichment.

    Attempts to:
    1. Create a scan job on the API.
    2. Poll until complete (status = "complete" or "failed").
    3. Fetch AI-enriched findings (exploitability scores + fix suggestions).

    Degrades gracefully:
    - No API key → prints a tip to run ``velonus auth login``.
    - API unreachable → warns and continues with local results.
    - API returns 501 (endpoint not yet live) → shows a notice.

    The local scan results (already displayed above) are always shown
    regardless of whether the API call succeeds.

    Args:
        findings: Filtered NormalizedFinding list from the local pipeline.
        target: Absolute path that was scanned.
        exclude_patterns: Glob exclusions passed to the pipeline.
    """
    client = client_from_config()

    if client is None:
        console.print(
            "\n[yellow]⚡ AI enrichment not enabled.[/yellow]\n"
            "  Run [bold]velonus auth login[/bold] to connect to the Velonus API\n"
            "  and get exploitability scores + AI-generated fixes.\n"
        )
        return

    # Skip AI submission if no findings worth enriching.
    eligible = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")]
    if not eligible:
        console.print(
            "\n[dim]--ai: no MEDIUM+ findings to enrich — skipping API submission.[/dim]\n"
        )
        return

    console.print(
        f"\n[bold green]⚡ AI enrichment[/bold green] — "
        f"submitting {len(eligible)} finding(s) to [cyan]{cli_config.get_api_url()}[/cyan] ...\n"
    )

    # Build source context for each finding: up to 20 lines before and after
    # the flagged line from the actual local file. The server stores this so
    # the AI has real code context even though it cannot access local paths.
    source_contexts: dict[str, str] = {}
    for f in eligible:
        ctx = _read_source_context(Path(f.file), f.line_start, f.code_snippet)
        if ctx:
            source_contexts[f.id] = ctx

    try:
        # Upload local findings for server-side AI triage.
        # The server stores them and queues AI triage without re-scanning
        # (the local Windows path is not accessible on Railway/Render).
        scan_resp = client.upload_scan(target, eligible, exclude_patterns, source_contexts)
        scan_id = str(scan_resp.get("scan_id", ""))
        if not scan_id:
            console.print(
                "[yellow]⚠ API did not return a scan_id — AI enrichment skipped.[/yellow]\n"
            )
            return

        console.print(f"  [dim]Scan ID: {scan_id}[/dim]")

        # Poll for completion (max ~60 seconds, 3s intervals, 20 attempts).
        # Matches the web dashboard's AI-triage grace window — triage is a
        # background job enqueued after the scan completes and can take
        # close to a minute for several MEDIUM+ findings (observed prod
        # timings: 19.5s-22s). The dashboard will show results once the
        # background triage job completes even if this loop times out.
        import time  # noqa: PLC0415

        _MAX_POLL_ATTEMPTS = 20  # 20 × 3s = 60s max
        _MAX_CONSECUTIVE_POLL_ERRORS = 3  # tolerate transient blips, not a dead connection
        timed_out = True
        consecutive_errors = 0

        for attempt in range(_MAX_POLL_ATTEMPTS):
            time.sleep(3)
            try:
                scan_status = client.get_scan(scan_id)
            except APIConnectionError:
                # A single dropped request shouldn't abort the whole poll —
                # only give up after several attempts in a row fail, since the
                # scan/triage job keeps running server-side regardless.
                consecutive_errors += 1
                if consecutive_errors >= _MAX_CONSECUTIVE_POLL_ERRORS:
                    raise
                continue
            consecutive_errors = 0
            status_val = str(scan_status.get("status", ""))
            if status_val in ("complete", "completed"):
                timed_out = False
                break
            if status_val == "failed":
                console.print(
                    f"  [red]✗ Scan job failed:[/red] {scan_status.get('error_message', 'unknown error')}\n"
                )
                return
            if attempt % 3 == 0:
                console.print(f"  [dim]Waiting for AI triage... ({(attempt + 1) * 3}s)[/dim]")

        if timed_out:
            console.print(
                "  [yellow]⚡ AI triage still running[/yellow] — "
                "results will be ready in your dashboard shortly.\n"
            )
            return

        # Fetch AI-enriched findings.
        ai_findings = client.get_findings(scan_id)
        if not ai_findings:
            console.print("  [dim]No AI-enriched findings returned.[/dim]\n")
            return

        _print_ai_summary(ai_findings)

    except APIError as exc:
        if exc.status_code == 501:
            console.print(
                "  [yellow]⚠ AI enrichment API not yet live (501).[/yellow]\n"
                "  The API is being built — local results shown above are complete.\n"
            )
        elif exc.status_code == 401:
            console.print(
                "  [red]✗ Invalid API key.[/red] "
                "Run [bold]velonus auth login[/bold] to re-authenticate.\n"
            )
        else:
            console.print(f"  [red]✗ API error {exc.status_code}:[/red] {exc.message}\n")
    except APIConnectionError as exc:
        console.print(
            f"  [red]✗ Cannot reach the Velonus API:[/red] {exc}\n"
            "  Check your network connection.\n"
        )


def _as_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _print_ai_summary(ai_findings: list[dict[str, object]]) -> None:
    """Print AI-enriched finding highlights to the terminal.

    Shows exploitability scores and fix availability for findings
    that have been enriched by the AI engine.

    Args:
        ai_findings: List of finding dicts from the API with AI fields populated.
    """
    from rich.table import Table  # noqa: PLC0415

    enriched = [f for f in ai_findings if f.get("exploitability_score") is not None]
    if not enriched:
        console.print("  [dim]AI triage complete — no additional prioritization data.[/dim]\n")
        return

    console.print(
        f"  [bold green]✓ AI triage complete[/bold green] — {len(enriched)} finding(s) scored:\n"
    )

    table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
    table.add_column("Score", justify="center", style="bold", width=6)
    table.add_column("Priority", justify="center", width=8)
    table.add_column("File", no_wrap=True)
    table.add_column("Explanation")
    table.add_column("Fix?", justify="center", width=5)

    for f in sorted(enriched, key=lambda x: _as_float(x.get("exploitability_score")), reverse=True):
        score = _as_float(f.get("exploitability_score"))
        priority = str(f.get("ai_priority", "—"))
        file_path = str(f.get("file_path", "—"))
        explanation = str(f.get("ai_explanation", ""))[:80]
        has_fix = "✓" if f.get("ai_remediation") else "—"

        score_color = "red" if score >= 0.7 else "yellow" if score >= 0.4 else "green"
        table.add_row(
            f"[{score_color}]{score:.2f}[/{score_color}]",
            priority,
            file_path,
            explanation,
            has_fix,
        )

    console.print(table)
    console.print()


class OutputFormat(StrEnum):
    """Supported output formats for scan results."""

    terminal = "terminal"
    json = "json"
    sarif = "sarif"


def _resolve_target(path: str) -> Path:
    """Resolve and validate the scan target path.

    Args:
        path: Raw string path provided by the user.

    Returns:
        Resolved absolute Path object.

    Raises:
        typer.BadParameter: If the path does not exist.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise typer.BadParameter(f"Path does not exist: {resolved}")
    return resolved


def _json_default(obj: object) -> str:
    """Custom JSON serializer for types not handled natively by json.dumps.

    - datetime → ISO 8601 string with T separator (e.g. "2026-05-11T12:34:56.789")
    - Everything else → str() fallback (covers any unexpected types)

    StrEnum values (Severity, Confidence) are NOT routed here because StrEnum
    inherits from str, so json.dumps already treats them as plain strings.
    """
    from datetime import datetime

    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _output_json(findings: list[NormalizedFinding]) -> None:
    """Serialize findings to JSON and write directly to sys.stdout.

    Writes to sys.stdout (not the Rich console) so the output is always
    clean and pipeable:
        velonus scan ./ --format json | python -m json.tool

    Args:
        findings: List of normalized findings to serialize.
    """
    import json
    import sys
    from dataclasses import asdict

    payload = json.dumps(
        [asdict(f) for f in findings],
        indent=2,
        default=_json_default,
    )
    sys.stdout.write(payload + "\n")


@app.callback(invoke_without_command=True)
def scan(
    path: Annotated[
        str,
        typer.Argument(help="Path to the project or file to scan."),
    ] = ".",
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: terminal, json, sarif."),
    ] = OutputFormat.terminal,
    min_severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to display: critical, high, medium, low, info.",
        ),
    ] = "info",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show verbose output including per-tool timing."),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option(
            "--sarif",
            help="Write findings to a SARIF file (default: velonus-results.sarif).",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output path for the SARIF file. Implies --sarif when set.",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help=(
                "Glob pattern to exclude from results. Repeatable. "
                "e.g. --exclude migrations/ --exclude */generated_*.py"
            ),
        ),
    ] = None,
    detectors: Annotated[
        list[str] | None,
        typer.Option(
            "--detectors",
            "-d",
            help=(
                "Detector(s) to run: secrets, bandit, semgrep, pip-audit, safety. "
                "Repeatable or comma-separated. Defaults to all five, or to "
                "~/.velonus/config.toml's [scan] detectors when set."
            ),
        ),
    ] = None,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help=(
                "Submit scan to the Velonus API for AI-powered prioritization "
                "and fix generation. Requires authentication (velonus auth login)."
            ),
        ),
    ] = False,
) -> None:
    """Run a security scan on the given path.

    Phase 1 pipeline: secrets + Bandit + Semgrep + pip-audit + Safety.
    Secrets run first (synchronous); all other tools run in parallel.

    Add [bold]--ai[/bold] to get exploitability scores and AI-generated fixes
    via the Velonus API (requires [dim]velonus auth login[/dim]).
    """
    target = _resolve_target(path)

    # Build exclusion pattern list: defaults + config file + CLI flags.
    # Config file patterns are additive on top of the defaults.
    # CLI --exclude patterns are further additive on top of both.
    exclude_patterns: list[str] = list(DEFAULT_EXCLUDE_PATTERNS)
    exclude_patterns.extend(_load_config_excludes())
    if exclude:
        exclude_patterns.extend(exclude)

    # Detector selection: CLI flag > config file > None (all five).
    # --detectors accepts repeated flags and/or comma-separated values.
    cli_detectors: list[str] | None = None
    if detectors:
        cli_detectors = [d.strip() for item in detectors for d in item.split(",") if d.strip()]
    selected_detectors = cli_detectors or _load_config_detectors()
    if selected_detectors is not None:
        unknown = set(selected_detectors) - ALL_DETECTORS
        if unknown:
            raise typer.BadParameter(
                f"Unknown detector(s): {sorted(unknown)}. "
                f"Valid options: {sorted(ALL_DETECTORS)}",
                param_hint="--detectors",
            )

    # Route all UI output to stderr when JSON or SARIF format is active so
    # that stdout contains only the machine-readable payload — making it
    # safely pipeable to jq / json.tool / SARIF-consuming tools.
    _machine_formats = (OutputFormat.json, OutputFormat.sarif)
    ui_console = _stderr_console if output_format in _machine_formats else console

    # Prompt to install optional tools (semgrep, trufflehog) on first use.
    # Only runs in interactive TTY sessions — silently skipped in CI/pipes.
    if output_format == OutputFormat.terminal:
        _prompt_optional_tools()

    if verbose:
        ui_console.print(f"[dim]Resolved target: {target}[/dim]")

    if output_format not in _machine_formats:
        console.print(f"\n[bold green]Velonus[/bold green] — scanning [cyan]{target}[/cyan]\n")

    findings: list[NormalizedFinding] = []

    # Per-tool progress table — shows each detector's status in real time.
    # Filtered to the selected detectors so a --detectors bandit run doesn't
    # show four rows stuck at "waiting..." forever.
    _enabled_tools = selected_detectors if selected_detectors is not None else sorted(ALL_DETECTORS)
    _ALL_TOOL_LABELS: dict[str, str] = {
        "secrets": "Secrets",
        "bandit": "Bandit",
        "semgrep": "Semgrep",
        "pip-audit": "pip-audit",
        "safety": "Safety",
    }
    _TOOL_LABELS: list[tuple[str, str]] = [
        (key, _ALL_TOOL_LABELS[key]) for key in ("secrets", "bandit", "semgrep", "pip-audit", "safety")
        if key in _enabled_tools
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<12}"),
        TimeElapsedColumn(),
        TextColumn("{task.fields[status]}"),
        console=ui_console,
        transient=True,
    ) as progress:
        tool_tasks: dict[str, TaskID] = {}
        for tool_key, tool_label in _TOOL_LABELS:
            tid = progress.add_task(
                f"[cyan]{tool_label}[/cyan]",
                total=1,
                status="[dim]waiting...[/dim]",
            )
            tool_tasks[tool_key] = tid

        def _on_tool_done(tool_name: str, count: int, elapsed: float) -> None:
            tid = tool_tasks.get(tool_name)
            if tid is not None:
                label = f"[green]✓[/green] [dim]{count} finding(s)[/dim]"
                progress.update(tid, completed=1, status=label)

        # Mark all selected tools as running immediately (they start concurrently,
        # except secrets which runs first — but the visual distinction isn't
        # worth the complexity here since both stages start right away).
        for tid in tool_tasks.values():
            progress.update(tid, status="[yellow]running[/yellow]")

        pipeline = ScanPipeline(exclude=exclude_patterns, detectors=selected_detectors)
        findings = asyncio.run(pipeline.run(target, verbose=verbose, on_tool_done=_on_tool_done))

    # Filter by minimum severity — applied before all output formats.
    # Dict lookup instead of list.index() avoids ValueError on unexpected severity values.
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_idx = sev_order.get(min_severity.lower(), 0)
    filtered = [f for f in findings if sev_order.get(f.severity.value.lower(), 0) >= min_idx]

    if output_format == OutputFormat.terminal:
        render_findings_table(filtered, target=str(target), console=console)
    elif output_format == OutputFormat.json:
        _output_json(filtered)
    elif output_format == OutputFormat.sarif:
        # --format sarif: print SARIF JSON to stdout (for piping / CI consumption)
        import json as _json

        console.print_json(_json.dumps(to_sarif(filtered, str(target))))

    # --sarif flag (or -o path): write findings to a file in addition to terminal/stdout output.
    # Format of the written file follows --format: json → JSON array, otherwise → SARIF.
    write_output_file = sarif or output is not None
    if write_output_file:
        if output_format == OutputFormat.json:
            # User passed --format json — write a JSON array, not SARIF.
            import json as _json
            from dataclasses import asdict as _asdict

            out_path = output if output is not None else Path("velonus-results.json")
            out_path.write_text(
                _json.dumps([_asdict(f) for f in filtered], indent=2, default=_json_default),
                encoding="utf-8",
            )
            ui_console.print(f"\n[dim]JSON report written to[/dim] [cyan]{out_path}[/cyan]")
        else:
            sarif_path = output if output is not None else Path("velonus-results.sarif")
            write_sarif(filtered, sarif_path, scan_path=str(target))
            ui_console.print(f"\n[dim]SARIF report written to[/dim] [cyan]{sarif_path}[/cyan]")

    # --ai: submit to the Velonus API for AI-powered prioritization + fix generation.
    # Pass the full (unfiltered) findings so the MEDIUM+ eligibility check inside
    # _run_ai_enrichment uses all findings — not just the ones visible at the user's
    # --severity display threshold. The server runs its own scan independently; the
    # client-side list is only used for the "skip if nothing worth enriching" guard.
    if ai:
        _run_ai_enrichment(findings, target=str(target), exclude_patterns=exclude_patterns)

    # Exit code 1 if any HIGH or CRITICAL findings (for CI gate integration)
    high_or_critical = [f for f in filtered if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if high_or_critical:
        ui_console.print(
            f"[dim]↳ Exiting with code 1 — {len(high_or_critical)} HIGH/CRITICAL "
            f"finding(s) detected (CI gate). "
            f"Adjust with [bold]--severity medium[/bold] to change the threshold.[/dim]\n"
        )
        raise typer.Exit(code=1)
