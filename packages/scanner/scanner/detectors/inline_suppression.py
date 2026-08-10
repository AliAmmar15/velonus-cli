"""Shared inline suppression marker — `# velonus: ignore [rule_id]` (Phase 7 / 5F).

Used by SecretsDetector and BanditRunner. Distinct from the legacy
`shield:ignore` marker in secrets.py, which drops a finding entirely and
isn't rule-scoped: this marker still lets the finding be created, just with
``suppressed=True`` set, so it stays visible (dimmed, filterable) in the
dashboard rather than disappearing without a trace.

Syntax, on the flagged line or the line immediately above it:
    api_key = "..."  # velonus: ignore
    api_key = "..."  # velonus: ignore [generic-api-key]
    # velonus: ignore[B105]
    api_key = "..."

Omitting the bracketed rule ID suppresses any rule on that line. A bracketed
ID only suppresses a matching rule (case-insensitive), so an unrelated
finding on the same line still surfaces normally.
"""

from __future__ import annotations

import re

_VELONUS_IGNORE_RE = re.compile(
    r"#\s*velonus\s*:\s*ignore(?:\s*\[\s*([^\]]+?)\s*\])?", re.IGNORECASE
)


def check_inline_suppression(rule_id: str, line_text: str, prev_line: str | None) -> bool:
    """Return True if a `# velonus: ignore [rule_id]` comment applies to *rule_id*.

    Checks the flagged line first, then the line immediately above it.
    """
    for candidate in (line_text, prev_line):
        if not candidate:
            continue
        match = _VELONUS_IGNORE_RE.search(candidate)
        if match is None:
            continue
        target = match.group(1)
        if target is None or target.strip().lower() == rule_id.lower():
            return True
    return False
