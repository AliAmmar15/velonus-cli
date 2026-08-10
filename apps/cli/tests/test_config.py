"""test_config.py — Unit tests for shield.core.config's TOML read/write layer.

Covers regressions found in review:
  - save()/load() round-trip for values containing TOML-special characters
    (backslashes, quotes, control chars) that previously corrupted the file
  - config.toml is written with restrictive (owner-only) permissions
  - set_value() on a known list-type key (scan.exclude) appends to an array
    instead of silently writing an unusable plain string
"""

from __future__ import annotations

import stat
from typing import TYPE_CHECKING

import pytest
from shield.core import config as cfg

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect VELONUS_DIR/CONFIG_PATH to a temp dir for every test in this file."""
    monkeypatch.setattr(cfg, "VELONUS_DIR", tmp_path)
    monkeypatch.setattr(cfg, "CONFIG_PATH", tmp_path / "config.toml")


class TestSaveLoadRoundTrip:
    """save() output must always be valid TOML that load() can parse back."""

    def test_plain_value_round_trips(self) -> None:
        cfg.set_credentials("vn_sk_plain", "https://example.com")
        assert cfg.get_api_key() == "vn_sk_plain"

    def test_backslash_in_value_round_trips(self) -> None:
        """Regression: an unescaped backslash (e.g. a Windows path) used to
        produce invalid TOML, causing load() to silently return {} — wiping
        out the stored API key along with it."""
        cfg.set_value("scan", "note", r"C:\Users\dev\repo")
        assert cfg.get_value("scan", "note") == r"C:\Users\dev\repo"
        # The API key set earlier in other tests must not be collateral
        # damage — verify the whole file still parses.
        assert cfg.load() != {}

    def test_backslash_does_not_corrupt_other_keys(self) -> None:
        cfg.set_credentials("vn_sk_abc123", "https://example.com")
        cfg.set_value("scan", "note", r"C:\Users\dev\repo")
        assert cfg.get_api_key() == "vn_sk_abc123"

    def test_quote_in_value_round_trips(self) -> None:
        cfg.set_value("scan", "note", 'has "quotes" inside')
        assert cfg.get_value("scan", "note") == 'has "quotes" inside'

    def test_list_value_with_backslash_round_trips(self) -> None:
        data = cfg.load()
        data["scan"] = {"exclude": [r"C:\Users\dev\repo", 'weird"quote']}
        cfg.save(data)
        loaded = cfg.load()
        assert loaded["scan"]["exclude"] == [r"C:\Users\dev\repo", 'weird"quote']

    def test_newline_and_control_chars_round_trip(self) -> None:
        cfg.set_value("scan", "note", "line1\nline2\ttabbed")
        assert cfg.get_value("scan", "note") == "line1\nline2\ttabbed"


class TestConfigFilePermissions:
    def test_config_file_is_owner_only(self) -> None:
        cfg.set_credentials("vn_sk_abc123")
        mode = stat.S_IMODE(cfg.CONFIG_PATH.stat().st_mode)
        assert mode == 0o600


class TestSetValueListKeys:
    """scan.exclude is a known list key — config set must append to an array."""

    def test_scan_exclude_is_written_as_list(self) -> None:
        cfg.set_value("scan", "exclude", "migrations/")
        data = cfg.load()
        assert data["scan"]["exclude"] == ["migrations/"]

    def test_scan_exclude_appends_without_overwriting(self) -> None:
        cfg.set_value("scan", "exclude", "migrations/")
        cfg.set_value("scan", "exclude", "generated/")
        data = cfg.load()
        assert data["scan"]["exclude"] == ["migrations/", "generated/"]

    def test_scan_exclude_dedupes(self) -> None:
        cfg.set_value("scan", "exclude", "migrations/")
        cfg.set_value("scan", "exclude", "migrations/")
        data = cfg.load()
        assert data["scan"]["exclude"] == ["migrations/"]

    def test_scan_exclude_supports_comma_separated_patterns(self) -> None:
        cfg.set_value("scan", "exclude", "migrations/, generated/")
        data = cfg.load()
        assert data["scan"]["exclude"] == ["migrations/", "generated/"]

    def test_non_list_key_still_writes_plain_string(self) -> None:
        cfg.set_value("auth", "api_url", "https://example.com")
        data = cfg.load()
        assert data["auth"]["api_url"] == "https://example.com"

    def test_scan_detectors_is_written_as_list(self) -> None:
        cfg.set_value("scan", "detectors", "bandit,semgrep")
        data = cfg.load()
        assert data["scan"]["detectors"] == ["bandit", "semgrep"]

    def test_scan_detectors_appends_without_overwriting(self) -> None:
        cfg.set_value("scan", "detectors", "bandit")
        cfg.set_value("scan", "detectors", "semgrep")
        data = cfg.load()
        assert data["scan"]["detectors"] == ["bandit", "semgrep"]
