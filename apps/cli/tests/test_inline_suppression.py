"""test_inline_suppression.py — Unit tests for the shared `# velonus: ignore`
marker used by SecretsDetector and BanditRunner (Phase 7 / 5F).
"""

# ruff: noqa: I001
from __future__ import annotations

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

from scanner.detectors.inline_suppression import check_inline_suppression  # noqa: E402


class TestCheckInlineSuppression:
    def test_no_marker_anywhere_returns_false(self) -> None:
        assert check_inline_suppression("B105", "PASSWORD = 'x'", None) is False

    def test_bare_marker_on_flagged_line_suppresses_any_rule(self) -> None:
        assert check_inline_suppression("B105", "x = 1  # velonus: ignore", None) is True

    def test_bare_marker_on_previous_line_suppresses(self) -> None:
        assert check_inline_suppression("B105", "x = 1", "# velonus: ignore") is True

    def test_bracketed_rule_id_matches_case_insensitively(self) -> None:
        assert check_inline_suppression("b105", "x = 1  # velonus: ignore [B105]", None) is True

    def test_bracketed_rule_id_mismatch_does_not_suppress(self) -> None:
        assert check_inline_suppression("B105", "x = 1  # velonus: ignore [B999]", None) is False

    def test_marker_requires_velonus_prefix(self) -> None:
        """A bare 'ignore' comment (no 'velonus:' prefix) must not suppress —
        otherwise every unrelated '# ignore' comment in a codebase would."""
        assert check_inline_suppression("B105", "x = 1  # ignore this", None) is False

    def test_whitespace_and_case_variations_in_marker_are_tolerated(self) -> None:
        assert check_inline_suppression("B105", "x = 1  #VELONUS:  IGNORE", None) is True

    def test_none_prev_line_does_not_crash(self) -> None:
        assert check_inline_suppression("B105", "x = 1", None) is False

    def test_empty_prev_line_does_not_crash(self) -> None:
        assert check_inline_suppression("B105", "x = 1", "") is False
