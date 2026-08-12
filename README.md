# velonus

[![PyPI](https://img.shields.io/pypi/v/velonus)](https://pypi.org/project/velonus/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

> AI-native application security scanner for developers.
> Finds real issues. Explains why they matter. Generates fixes.

This repo is the **open-source scanner core** of [Velonus](https://velonus.com):
the CLI, the scan pipeline (`packages/scanner`), and finding
normalization/deduplication (`packages/normalizer`). Running `velonus scan`
locally never sends your code anywhere — it's fully self-contained.

The AI triage/remediation engine, GitHub App integration (one-click fix PRs
with generated regression tests), and web dashboard are part of the hosted
Velonus platform and are proprietary — `velonus scan --ai` talks to that API,
everything else in this repo runs entirely on your machine.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [velonus scan](#velonus-scan)
  - [velonus auth](#velonus-auth)
  - [velonus config](#velonus-config)
  - [velonus pr review](#velonus-pr-review)
  - [velonus ci](#velonus-ci)
- [Output Formats](#output-formats)
- [Severity Levels](#severity-levels)
- [CI/CD Integration](#cicd-integration)
- [What's under the hood](#whats-under-the-hood)
- [License](#license)

---

## Installation

### Requirements

- Python 3.10+
- Windows / macOS / Linux

### Install via pip

```bash
pip install velonus
```

This installs the CLI plus Bandit, pip-audit, and Safety (the core scanner
tools). Two extras add more coverage:

```bash
pip install velonus[semgrep]          # Semgrep ruleset (~200MB, optional)
pip install velonus[detect-secrets]   # detect-secrets, higher-fidelity secret scanning
pip install velonus[semgrep,detect-secrets]
```

Verify install:

```bash
velonus --version
```

---

## Quick Start

```bash
# Scan the current directory
velonus scan ./

# Scan a specific project
velonus scan ./my-python-project

# Only show HIGH and CRITICAL findings
velonus scan ./ --severity high

# Output as JSON (for piping or tooling)
velonus scan ./ --format json

# Submit to the Velonus API for AI triage + fix suggestions (requires `velonus auth login`)
velonus scan ./ --ai
```

---

## Commands

### `velonus scan`

Runs the security scanner pipeline (secrets, Bandit, Semgrep, pip-audit,
Safety) on a local path and prints findings to the terminal.

```
velonus scan [PATH] [OPTIONS]
```

| Argument / Option | Default | Description |
|---|---|---|
| `PATH` | `.` | Path to the project or file to scan |
| `--format`, `-f` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `--severity`, `-s` | `info` | Minimum severity to show: `critical`, `high`, `medium`, `low`, `info` |
| `--verbose`, `-v` | off | Show per-tool timing and extra detail |
| `--sarif` | off | Write findings to `velonus-results.sarif` |
| `--output`, `-o` | | Custom SARIF output path (implies `--sarif`) |
| `--exclude`, `-e` | | Glob pattern to exclude, repeatable (e.g. `--exclude migrations/`) |
| `--detectors`, `-d` | all five | Restrict to specific detectors: `secrets`, `bandit`, `semgrep`, `pip-audit`, `safety` |
| `--ai` | off | Submit to the Velonus API for AI triage + fix generation (requires `velonus auth login`) |
| `--help` | | Show help and exit |

#### Examples

```bash
velonus scan ./                                       # scan current directory
velonus scan ./ --severity high                        # only critical + high
velonus scan ./ --exclude migrations/ --exclude '*/generated_*.py'
velonus scan ./ --detectors bandit,semgrep              # only run these two
velonus scan ./ --format json > findings.json
velonus scan ./ --sarif                                 # for GitHub Code Scanning
```

#### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no HIGH or CRITICAL findings |
| `1` | Scan completed, one or more HIGH or CRITICAL findings found |

Exit code `1` on HIGH/CRITICAL is intentional — use it as a CI gate to block merges.

---

### `velonus auth`

Manages authentication with the Velonus API (only needed for `--ai`, `pr review`).

```bash
velonus auth login    # prompts for API key, verifies it, stores it in ~/.velonus/config.toml
velonus auth logout   # clears stored credentials
velonus auth status   # shows masked key + live connectivity check
```

---

### `velonus config`

Manages local CLI configuration at `~/.velonus/config.toml`.

```bash
velonus config show
velonus config set scan.detectors bandit,semgrep
```

---

### `velonus pr review`

Runs an on-demand AI-assisted review of an open GitHub pull request (requires
`velonus auth login` and a connected GitHub App installation on the hosted
platform).

```bash
velonus pr review https://github.com/org/repo/pull/123
```

---

### `velonus ci`

Generates a ready-to-use CI workflow file that runs Velonus and uploads SARIF
to GitHub code scanning.

```bash
velonus ci --generate-workflow                        # writes .github/workflows/velonus.yml
velonus ci --generate-workflow --provider github-actions --output custom/path.yml
```

---

## Output Formats

### `terminal` (default)

Colored Rich table with severity badges, file paths, line numbers, rule IDs,
and messages.

```
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity       ┃ Tool       ┃ File          ┃ Line  ┃ Rule             ┃ Message                      ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 🔴 CRITICAL    │ secrets    │ config.py     │ 12    │ aws-access-key   │ Hardcoded AWS access key…    │
│ 🟠 HIGH        │ bandit     │ auth/views.py │ 87    │ B106             │ Hardcoded password in func…  │
│ 🟡 MEDIUM      │ semgrep    │ db/query.py   │ 43    │ python.sqli      │ Possible SQL injection…      │
└────────────────┴────────────┴───────────────┴───────┴──────────────────┴──────────────────────────────┘

Total: 3 findings  —  1 CRITICAL  1 HIGH  1 MEDIUM
```

### `json`

A JSON array of `NormalizedFinding` objects — suitable for piping into other tools.

```bash
velonus scan ./ --format json | python -m json.tool
```

### `sarif`

Static Analysis Results Interchange Format 2.1.0 — compatible with GitHub
Code Scanning, VS Code's SARIF Viewer, and other SAST tooling.

---

## Severity Levels

| Badge | Level | When it's used |
|---|---|---|
| 🔴 | `CRITICAL` | Hardcoded secrets, RCE, auth bypass |
| 🟠 | `HIGH` | SQL injection, command injection, insecure deserialization |
| 🟡 | `MEDIUM` | XSS, weak crypto, path traversal |
| 🔵 | `LOW` | Insecure defaults, minor misconfigurations |
| ⚪ | `INFO` | Style issues, informational notes |

---

## CI/CD Integration

Generate a workflow automatically:

```bash
velonus ci --generate-workflow
```

Or add this manually to `.github/workflows/security.yml`:

```yaml
name: Velonus Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install velonus
      - run: velonus scan ./ --severity high
        # exits 1 on HIGH/CRITICAL findings — blocks the merge
```

### Pre-commit hook

```yaml
repos:
  - repo: local
    hooks:
      - id: velonus-scan
        name: Velonus Security Scan
        entry: velonus scan
        args: ["./", "--severity", "high"]
        language: system
        pass_filenames: false
```

---

## What's under the hood

- **`apps/cli`** — Typer CLI, Rich terminal output, config management, API client for `--ai`/`pr review`/`auth`.
- **`packages/scanner`** — parallel wrappers around Bandit, Semgrep, pip-audit, Safety, and secret detection (detect-secrets + entropy fallback). Nothing here is a reimplementation of these tools — Velonus orchestrates and normalizes their output.
- **`packages/normalizer`** — converts every tool's raw output into one `NormalizedFinding` shape, maps CWE/OWASP, and deduplicates (exact fingerprint + cross-tool same-location merge).

This pipeline was built to be scanner-agnostic at the finding level — Python
via these five tools is the first target, with more language/tool coverage
planned.

---

## License

MIT — this repo (CLI + scanner core) is fully open source.
The AI triage/remediation engine, GitHub App integration, and web dashboard
that power `--ai` and `pr review` are part of the proprietary hosted
platform at [velonus.io](https://velonus.io).
