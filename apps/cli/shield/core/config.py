"""CLI configuration management — reads and writes ~/.velonus/config.toml.

Stores:
  [auth]
    api_key = "vn_sk_..."
    api_url = "https://velonus-production.up.railway.app"

  [scan]
    exclude = ["tests/", "conftest.py"]

The file is created on first `velonus auth login`. All other commands read it
if present and return defaults when it is missing.

Note: tomllib (Python 3.11+ stdlib) handles reading. Writing is done with a
minimal hand-rolled serialiser — the config structure is simple enough that
a full TOML library would be overkill.
"""

from __future__ import annotations

import contextlib
import tomllib
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

VELONUS_DIR: Path = Path.home() / ".velonus"
CONFIG_PATH: Path = VELONUS_DIR / "config.toml"
DEFAULT_API_URL: str = "https://velonus-production.up.railway.app"


# ---------------------------------------------------------------------------
# Low-level load / save
# ---------------------------------------------------------------------------


def load() -> dict[str, Any]:
    """Load the config file.

    Returns an empty dict when the file is missing. Prints a user-facing
    warning on PermissionError or malformed TOML so the problem is visible,
    then returns {} so callers degrade to defaults rather than crashing.
    """
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("rb") as fh:
            return tomllib.load(fh)
    except PermissionError:
        import sys

        print(
            f"Warning: {CONFIG_PATH} is not readable — check file permissions.",
            file=sys.stderr,
        )
        return {}
    except tomllib.TOMLDecodeError as exc:
        import sys

        print(
            f"Warning: {CONFIG_PATH} is malformed and will be ignored ({exc}).",
            file=sys.stderr,
        )
        return {}


def _toml_escape_string(value: str) -> str:
    """Escape *value* for use inside a TOML basic string (double-quoted).

    Backslash MUST be escaped first — escaping it after other characters
    would double-escape the backslashes those substitutions introduce.
    Covers all characters TOML's basic-string grammar requires escaping:
    backslash, double quote, and the C0 control characters (newline, tab,
    carriage return, backspace, form feed, and any other \\x00-\\x1f).
    Unescaped control characters or backslashes make the file unparsable —
    this previously corrupted config.toml (including the stored API key)
    for any value containing one, e.g. a Windows path in --exclude.
    """
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    out = out.replace("\b", "\\b").replace("\f", "\\f")
    return "".join(f"\\u{ord(ch):04x}" if ord(ch) < 0x20 else ch for ch in out)


def save(data: dict[str, Any]) -> None:
    """Persist the config dict to ~/.velonus/config.toml.

    Creates the directory and file if they do not exist.
    Sections and values are written in deterministic order.
    The file is created with 0600 permissions (owner read/write only) since
    it may contain a plaintext API key.

    Args:
        data: Dict of {section: {key: value}} — only str, int, bool, and
              list[str] values are supported (covers all current config fields).
    """
    VELONUS_DIR.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for section, values in data.items():
        lines.append(f"[{section}]")
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, list):
                items = ", ".join(f'"{_toml_escape_string(str(v))}"' for v in value)
                lines.append(f"{key} = [{items}]")
            elif isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif isinstance(value, int):
                lines.append(f"{key} = {value}")
            else:
                lines.append(f'{key} = "{_toml_escape_string(str(value))}"')
        lines.append("")
    CONFIG_PATH.write_text("\n".join(lines), encoding="utf-8")
    # Best-effort — e.g. unsupported on some filesystems/platforms.
    with contextlib.suppress(OSError):
        CONFIG_PATH.chmod(0o600)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def get_api_key() -> str | None:
    """Return the stored API key, or None if not set."""
    return load().get("auth", {}).get("api_key") or None


def get_api_url() -> str:
    """Return the configured API URL, defaulting to the hosted service."""
    return load().get("auth", {}).get("api_url") or DEFAULT_API_URL


def set_credentials(api_key: str, api_url: str = DEFAULT_API_URL) -> None:
    """Persist the API key and URL to the config file.

    Merges into any existing config so that [scan] settings are preserved.

    Args:
        api_key: Velonus API key obtained from the dashboard.
        api_url: API base URL (default: https://velonus-production.up.railway.app).
    """
    data = load()
    data.setdefault("auth", {})
    data["auth"]["api_key"] = api_key
    data["auth"]["api_url"] = api_url
    save(data)


def clear_credentials() -> None:
    """Remove the stored API key and URL from the config file.

    Other config sections (e.g. [scan]) are preserved.
    """
    data = load()
    data.pop("auth", None)
    save(data)


# ---------------------------------------------------------------------------
# Generic key/value helpers (used by `velonus config set`)
# ---------------------------------------------------------------------------


def get_value(section: str, key: str) -> str | None:
    """Read a single value from the config file.

    Args:
        section: TOML table name (e.g. "scan").
        key: Key within that table (e.g. "exclude").

    Returns:
        The value as a string (or None if not found).
    """
    raw = load().get(section, {}).get(key)
    return str(raw) if raw is not None else None


# (section, key) pairs that are stored as a TOML array rather than a plain
# string. `config set` on one of these appends comma-separated patterns to
# the existing list instead of overwriting it with a single string — a bare
# string here would previously be silently ignored by every reader (e.g.
# _load_config_excludes()), which requires `isinstance(raw, list)`.
_LIST_KEYS: frozenset[tuple[str, str]] = frozenset({("scan", "exclude"), ("scan", "detectors")})


def set_value(section: str, key: str, value: str) -> None:
    """Write a single key/value pair under a TOML section.

    Merges into the existing config without touching other keys. For known
    list-type keys (see ``_LIST_KEYS``, e.g. ``scan.exclude``), *value* is
    split on commas and the resulting patterns are appended to the existing
    list (deduplicated, order-preserving) rather than overwriting it with a
    single string — matching what config readers expect for that key.

    Args:
        section: TOML table name (e.g. "scan").
        key: Key to set (e.g. "api_url").
        value: String value to store (or comma-separated values for list keys).
    """
    data = load()
    data.setdefault(section, {})

    if (section, key) in _LIST_KEYS:
        existing = data[section].get(key, [])
        if not isinstance(existing, list):
            existing = []
        new_items = [v.strip() for v in value.split(",") if v.strip()]
        merged = list(existing)
        for item in new_items:
            if item not in merged:
                merged.append(item)
        data[section][key] = merged
    else:
        data[section][key] = value

    save(data)
