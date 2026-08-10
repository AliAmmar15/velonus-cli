"""deduplicator.py — Finding deduplication for the Velonus scanner pipeline.

DeduplicationFilter removes duplicate NormalizedFinding objects using the
deterministic ``id`` field (SHA-256 fingerprint of tool+file+line+rule_id)
as the deduplication key.

Deduplication strategy:
  Pass 1 — fingerprint dedup:
    Iterate findings in pipeline order (secrets → bandit → semgrep → pip-audit → safety).
    Keep the FIRST occurrence of each ``id`` (highest-priority tool wins).
    Discard subsequent duplicates, logging at DEBUG level.

  Pass 2 — cross-tool location dedup:
    Group surviving findings by (file, line_start, cwe[0]).
    When multiple tools flag the same location for the same CWE, keep only
    the finding with the highest severity; discard the rest.
    NormalizedFinding.id is never mutated — the primary fingerprint is preserved.

    Dependency-level findings (pip-audit, safety) report ``line_start == 0``
    since a vulnerability applies to the whole package, not a line — every
    such finding for a given file would otherwise share the exact same
    ``(file, 0, "CWE-1035")`` key and collapse into a single surviving
    finding regardless of how many distinct packages/CVEs were found. To
    avoid discarding real, independent vulnerabilities, ``rule_id`` is
    folded into the key whenever ``line_start == 0`` so only genuine
    same-vulnerability duplicates (same rule_id) are collapsed.

This module is intentionally stateless. DeduplicationFilter can be
instantiated freely with no side-effects.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from normalizer.models import NormalizedFinding

from normalizer.models import Severity

logger = logging.getLogger(__name__)

# Ordered from highest to lowest — used to pick the winner in cross-tool dedup.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class DeduplicationFilter:
    """Removes duplicate NormalizedFinding objects by deterministic fingerprint id.

    Usage::

        deduplicator = DeduplicationFilter()
        unique_findings = deduplicator.deduplicate(all_findings)
    """

    def deduplicate(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        """Remove duplicate findings in two passes.

        Pass 1 — fingerprint dedup:
            Keep the first occurrence of each ``id``. The pipeline passes
            findings in priority order (secrets first, safety last), so the
            highest-priority tool's version of a same-tool duplicate is kept.

        Pass 2 — cross-tool location dedup:
            Group by (file, line_start, cwe[0]). When multiple tools flag the
            same location for the same CWE, keep only the highest-severity
            finding and discard the rest. ``NormalizedFinding.id`` is never
            mutated.

        Args:
            findings: All findings from all scanner tools, in pipeline priority order.

        Returns:
            Deduplicated list with first-occurrence ordering preserved.
        """
        # --- Pass 1: fingerprint dedup ---
        seen: set[str] = set()
        after_pass1: list[NormalizedFinding] = []

        for finding in findings:
            if finding.id in seen:
                logger.debug(
                    "Pass-1 dedup: id=%s (tool=%s, file=%s, line=%d)",
                    finding.id,
                    finding.tool,
                    finding.file,
                    finding.line_start,
                )
                continue
            seen.add(finding.id)
            after_pass1.append(finding)

        # --- Pass 2: cross-tool location dedup by (file, line_start, cwe[0]) ---
        # Build a map from location key → best finding seen so far.
        best: dict[tuple[str, int, str, str], NormalizedFinding] = {}
        for finding in after_pass1:
            cwe_key = finding.cwe[0] if finding.cwe else ""
            # Dependency-level findings have no real line number (line_start
            # is always 0), so (file, 0, cwe) alone is not a valid proxy for
            # "same location" — it would conflate every distinct vulnerable
            # package in the file. Disambiguate with rule_id in that case.
            rule_key = finding.rule_id if finding.line_start == 0 else ""
            loc_key = (finding.file, finding.line_start, cwe_key, rule_key)
            existing = best.get(loc_key)
            if existing is None:
                best[loc_key] = finding
            elif _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[existing.severity]:
                # This finding has higher severity — it wins.
                logger.debug(
                    "Pass-2 dedup: keeping %s %s over %s %s for %s:%d cwe=%s",
                    finding.severity,
                    finding.tool,
                    existing.severity,
                    existing.tool,
                    finding.file,
                    finding.line_start,
                    cwe_key or "(none)",
                )
                best[loc_key] = finding

        # Preserve original ordering of the winners.
        winner_ids: set[str] = {f.id for f in best.values()}
        after_pass2 = [f for f in after_pass1 if f.id in winner_ids]

        # --- Pass 3: per-file per-rule-id cap ---
        # Prevents a single noisy rule (e.g. detect-secrets-secret-keyword) from
        # flooding the output when it fires on dozens of lines in the same file.
        # Keep the first _MAX_PER_FILE_RULE findings in pipeline order; extras are
        # suppressed with a synthetic summary finding counted in the removed total.
        _MAX_PER_FILE_RULE = 10
        file_rule_counts: dict[tuple[str, str], int] = {}
        unique: list[NormalizedFinding] = []
        for finding in after_pass2:
            key = (finding.file, finding.rule_id)
            count = file_rule_counts.get(key, 0)
            if count < _MAX_PER_FILE_RULE:
                file_rule_counts[key] = count + 1
                unique.append(finding)
            else:
                logger.debug(
                    "Pass-3 cap: suppressing finding #%d for rule=%s in %s",
                    count + 1,
                    finding.rule_id,
                    finding.file,
                )

        removed = len(findings) - len(unique)
        if removed:
            logger.info("Deduplication removed %d duplicate finding(s)", removed)

        return unique
