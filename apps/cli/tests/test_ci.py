"""test_ci.py — Unit tests for the `velonus ci` command.

Covers:
  - --generate-workflow with no stored credentials exits 1 with a login hint
  - no flag at all is a documented no-op, not a silent no-op
  - --generate-workflow writes the fetched template to its default path
  - --output overrides the destination path
  - an existing destination file requires confirmation before overwrite
  - an APIError from the client surfaces as a friendly message and exit 1
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from shield.commands import ci
from shield.core.api_client import APIError
from typer.testing import CliRunner

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()


def _fake_client(
    content: str = "name: Velonus\n",
    filename: str = ".github/workflows/velonus.yml",
) -> MagicMock:
    client = MagicMock()
    client.get_ci_template.return_value = {
        "provider": "github-actions",
        "filename": filename,
        "content": content,
    }
    return client


def test_generate_workflow_without_auth_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ci, "client_from_config", lambda: None)
    result = runner.invoke(ci.app, ["--generate-workflow"])
    assert result.exit_code == 1
    assert "velonus auth login" in result.stdout


def test_no_flag_is_a_documented_noop() -> None:
    result = runner.invoke(ci.app, [])
    assert result.exit_code == 0
    assert "--generate-workflow" in result.stdout


def test_generate_workflow_writes_template_to_default_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ci, "client_from_config", lambda: _fake_client())

    result = runner.invoke(ci.app, ["--generate-workflow"])
    assert result.exit_code == 0, result.stdout

    dest = tmp_path / ".github" / "workflows" / "velonus.yml"
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == "name: Velonus\n"


def test_generate_workflow_respects_output_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ci, "client_from_config", lambda: _fake_client())
    dest = tmp_path / "custom" / "workflow.yml"

    result = runner.invoke(ci.app, ["--generate-workflow", "--output", str(dest)])
    assert result.exit_code == 0, result.stdout
    assert dest.read_text(encoding="utf-8") == "name: Velonus\n"


def test_generate_workflow_prompts_before_overwrite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dest = tmp_path / "existing.yml"
    dest.write_text("old content", encoding="utf-8")
    monkeypatch.setattr(ci, "client_from_config", lambda: _fake_client())

    declined = runner.invoke(
        ci.app, ["--generate-workflow", "--output", str(dest)], input="n\n"
    )
    assert declined.exit_code == 0
    assert dest.read_text(encoding="utf-8") == "old content"

    accepted = runner.invoke(
        ci.app, ["--generate-workflow", "--output", str(dest)], input="y\n"
    )
    assert accepted.exit_code == 0
    assert dest.read_text(encoding="utf-8") == "name: Velonus\n"


def test_generate_workflow_surfaces_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get_ci_template.side_effect = APIError(422, "Unsupported provider.")
    monkeypatch.setattr(ci, "client_from_config", lambda: client)

    result = runner.invoke(ci.app, ["--generate-workflow", "--provider", "gitlab-ci"])
    assert result.exit_code == 1
    assert "Unsupported provider." in result.stdout
