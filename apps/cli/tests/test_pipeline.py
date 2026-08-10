"""test_pipeline.py — Unit tests for ScanPipeline's `detectors` selection.

Coverage targets:
  - ScanPipeline() with no `detectors` arg runs all five tools (unchanged
    default behaviour).
  - ScanPipeline(detectors=[...]) only invokes the selected detectors —
    the rest are never called at all, not just filtered from the output.
  - An unknown detector name raises ValueError at construction time with a
    message listing the valid options.
  - "secrets" runs in stage 1 (synchronous) independently of the stage-2
    parallel selection.

Each detector's `.scan()` is replaced with a MagicMock so no subprocess
tools need to be installed and no filesystem scanning happens.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

from scanner.detectors.secrets import RawFinding  # noqa: E402
from scanner.pipeline import ALL_DETECTORS, ScanPipeline  # noqa: E402


def _finding(tool: str) -> RawFinding:
    # Distinct file per tool so DeduplicationFilter's cross-tool
    # same-location collapsing (see test_normalizer.py) never kicks in here —
    # these tests are about which detectors *run*, not dedup behaviour.
    return RawFinding(
        tool=tool,
        rule_id=f"{tool}-rule",
        file=f"/tmp/{tool}.py",
        line=1,
        severity="LOW",
        message="test finding",
        code_snippet="",
    )


def _stub_all_detectors(pipeline: ScanPipeline) -> dict[str, MagicMock]:
    """Replace every detector's .scan with a MagicMock returning one finding.

    Returns the {name: mock} map so tests can assert call/no-call.
    """
    mocks = {
        "secrets": MagicMock(return_value=[_finding("secrets")]),
        "bandit": MagicMock(return_value=[_finding("bandit")]),
        "semgrep": MagicMock(return_value=[_finding("semgrep")]),
        "pip-audit": MagicMock(return_value=[_finding("pip-audit")]),
        "safety": MagicMock(return_value=[_finding("safety")]),
    }
    pipeline._secrets.scan = mocks["secrets"]
    pipeline._bandit.scan = mocks["bandit"]
    pipeline._semgrep.scan = mocks["semgrep"]
    pipeline._pip_audit.scan = mocks["pip-audit"]
    pipeline._safety.scan = mocks["safety"]
    return mocks


def test_all_detectors_constant_matches_known_tools() -> None:
    assert {"secrets", "bandit", "semgrep", "pip-audit", "safety"} == ALL_DETECTORS


def test_unknown_detector_raises_value_error() -> None:
    with pytest.raises(ValueError, match="nonsense"):
        ScanPipeline(detectors=["bandit", "nonsense"])


def test_default_runs_all_five_detectors(tmp_path: Path) -> None:
    pipeline = ScanPipeline()
    mocks = _stub_all_detectors(pipeline)

    findings = asyncio.run(pipeline.run(tmp_path))

    for mock in mocks.values():
        mock.assert_called_once()
    assert {f.tool for f in findings} == {"secrets", "bandit", "semgrep", "pip-audit", "safety"}


def test_detectors_filter_skips_disabled_tools_entirely(tmp_path: Path) -> None:
    pipeline = ScanPipeline(detectors=["bandit", "secrets"])
    mocks = _stub_all_detectors(pipeline)

    findings = asyncio.run(pipeline.run(tmp_path))

    mocks["secrets"].assert_called_once()
    mocks["bandit"].assert_called_once()
    mocks["semgrep"].assert_not_called()
    mocks["pip-audit"].assert_not_called()
    mocks["safety"].assert_not_called()
    assert {f.tool for f in findings} == {"secrets", "bandit"}


def test_single_detector_selection(tmp_path: Path) -> None:
    pipeline = ScanPipeline(detectors=["safety"])
    mocks = _stub_all_detectors(pipeline)

    findings = asyncio.run(pipeline.run(tmp_path))

    mocks["secrets"].assert_not_called()
    mocks["bandit"].assert_not_called()
    mocks["semgrep"].assert_not_called()
    mocks["pip-audit"].assert_not_called()
    mocks["safety"].assert_called_once()
    assert [f.tool for f in findings] == ["safety"]
