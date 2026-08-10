"""
secrets.py — Secret detection for the Velonus scanner pipeline.

PIPELINE ORDER: SecretScanner ALWAYS runs first. See pipeline.py for execution
order. Rationale: secrets are the highest-risk finding class and must be surfaced
before any other tool result can deprioritize them.

Detection strategy (in order of preference):
  1. detect-secrets subprocess wrapper  — industry standard, actively maintained
  2. Entropy-based regex fallback       — runs automatically when detect-secrets is missing

The fallback covers: AWS access/secret keys, OpenAI API keys, GitHub tokens,
hardcoded JWTs, PEM private keys, generic API keys, database connection strings.

Both paths return list[RawFinding] with identical shape.
The caller (normalizer) converts RawFinding → NormalizedFinding with deterministic
IDs, CWE-798/A07:2021 mappings, and deduplication.
"""

from __future__ import annotations

import json
import logging
import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scanner.detectors.inline_suppression import check_inline_suppression

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline metadata
# ---------------------------------------------------------------------------

# PIPELINE ORDER: This constant is read by pipeline.py to enforce that secrets
# always run before Bandit/Semgrep/pip-audit. Lower number = earlier execution.
PIPELINE_PRIORITY: int = 0

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Shannon entropy threshold. Strings above this are treated as likely secrets.
# 4.5 bits is well above normal English text (~3.5) but below true random (~6.0).
_ENTROPY_THRESHOLD: float = 4.5

# Directories to skip during recursive file walking.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".eggs",
        ".next",  # Next.js build output
        ".ruff_cache",
        "docs",  # Documentation — keyword hits here are always FPs
        "examples",  # Example code — placeholder credentials by design
        "testdata",  # Test fixtures — often contain intentional fake secrets
    }
)

# File extensions to skip — binary, compiled, lock, and media files.
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pyc",
        ".pyo",
        ".lock",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".map",
        ".sarif",  # Scanner output — contains SHA-256 fingerprints
        ".tsbuildinfo",  # TypeScript incremental build cache
        ".hot-update.js",  # Webpack HMR chunks
        ".md",  # Markdown documentation
        ".rst",  # reStructuredText documentation
        ".txt",  # Plain text — rarely contains live secrets
        ".txtar",  # Go test archive format
    }
)

# Each entry: (rule_id, compiled_pattern, human_readable_message).
# Order matters — more specific patterns first to avoid duplicate matches.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "aws-access-key-id",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "AWS Access Key ID detected — rotate immediately via AWS IAM",
    ),
    (
        "aws-secret-access-key",
        re.compile(
            r"(?i)(?:aws.{0,20}secret|secret.{0,20}access)"
            r"\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        "AWS Secret Access Key detected — rotate immediately via AWS IAM",
    ),
    (
        "openai-api-key",
        re.compile(r"\b(sk-[A-Za-z0-9]{48})\b"),
        "OpenAI API Key detected — revoke at platform.openai.com/account/api-keys",
    ),
    (
        "openai-api-key-project",
        re.compile(r"\b(sk-proj-[A-Za-z0-9\-_]{48,255})\b"),
        "OpenAI project-scoped API Key detected — revoke at platform.openai.com",
    ),
    (
        "github-token",
        re.compile(
            r"\b("
            r"ghp_[A-Za-z0-9]{36}"
            r"|gho_[A-Za-z0-9]{36}"
            r"|ghs_[A-Za-z0-9]{36}"
            r"|github_pat_[A-Za-z0-9_]{82}"
            r")\b"
        ),
        "GitHub Personal Access Token detected — revoke at github.com/settings/tokens",
    ),
    (
        "jwt-hardcoded",
        re.compile(r"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b"),
        "Hardcoded JWT token found in source — never commit live tokens to version control",
    ),
    (
        "pem-private-key",
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----"),
        "PEM Private Key block detected — never commit private keys to version control",
    ),
    (
        "generic-api-key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|x-api-key)"
            r"\s*[=:]\s*[\"']([A-Za-z0-9\-_]{16,64})[\"']"
        ),
        "Generic API key assignment detected — verify this is not a live credential",
    ),
    (
        "db-connection-string",
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
            r"://[^\s\"'<>\r\n]{8,}"
        ),
        "Database connection string with embedded credentials detected",
    ),
]

# Catches `SECRET = "value"` / `api_key: "value"` assignments for entropy check.
# Negative lookbehind on [a-zA-Z] prevents matching keywords that are
# suffixes of other words (e.g. "monkey" contains "key", "donkey" too).
_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)"
    r"(?<![a-zA-Z])(?:key|secret|token|password|passwd|pwd|credential|private[_\-]?key|auth)"
    r"\s*[=:]\s*[\"']([^\"']{8,})[\"']"
)

# Broad patterns that fire on any keyword+assignment regardless of the RHS value.
# These require a higher minimum entropy on the matched value to reduce FPs on
# env-var references ("$API_KEY"), empty strings, and simple config keys.
_HIGH_ENTROPY_REQUIRED: frozenset[str] = frozenset(
    {
        "generic-api-key",
        "db-connection-string",
    }
)
_MIN_ENTROPY_FOR_GENERIC: float = 3.5

# Substrings that indicate a matched value is a placeholder/example.
# Checked case-insensitively inside the extracted RHS value.
_PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {
        "example",
        "placeholder",
        "changeme",
        "your-",
        "your_",
        "fake",
        "dummy",
        "sample",
        "demo",
        "xxx",
        "replace",
        "insert",
        "todo",
        "fixme",
    }
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RawFinding:
    """Pre-normalization finding shape produced by each scanner tool.

    All detector wrappers return list[RawFinding]. The Phase 1 normalizer
    converts these to NormalizedFinding with deterministic IDs, CWE/OWASP
    mappings, and cross-scan deduplication.

    Note: severity is a plain string (not the Severity enum) so that
    packages/scanner has zero runtime dependency on apps/cli.
    """

    tool: str  # "secrets" | "bandit" | "semgrep" | "pip-audit"
    rule_id: str  # e.g. "aws-access-key-id", "trufflehog-aws"
    file: str  # absolute path string
    line: int  # 1-indexed line number
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    message: str  # human-readable description of the finding
    code_snippet: str  # redacted source line — never store plaintext secrets here
    metadata: dict[str, Any] = field(default_factory=dict)
    # Set when a `# velonus: ignore [rule_id]` comment matched this finding's
    # line (or the line above it) — see inline_suppression.py.
    suppressed: bool = False


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits) for the given string.

    Typical ranges:
      0.0 – 2.4  — plain text, repeated characters, or short placeholders
      2.5 – 4.4  — moderate entropy (hex strings, short identifiers)
      4.5+       — high entropy (base64, random secrets, API keys)

    Args:
        data: Input string to measure.

    Returns:
        Entropy in bits as a float. Returns 0.0 for empty input.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_placeholder_value(value: str) -> bool:
    """Return True if value is a documentation placeholder rather than a live secret.

    Checks for angle-bracket templates (<YOUR_KEY>) and common placeholder words.
    """
    if "<" in value or ">" in value:
        return True
    lower = value.lower()
    return any(token in lower for token in _PLACEHOLDER_TOKENS)


def _is_suppressed(line_text: str, prev_line: str | None) -> bool:
    """Return True when a shield:ignore comment suppresses findings on this line.

    The comment can appear on the flagged line itself or on the line immediately above it:
        secret_key = "abc..."  # shield:ignore
    or:
        # shield:ignore
        secret_key = "abc..."
    """
    marker = "shield:ignore"
    return marker in line_text.lower() or (prev_line is not None and marker in prev_line.lower())


def _entropy_confidence(entropy: float) -> str:
    """Map Shannon entropy bits to a detection confidence label.

    Returns:
        "HIGH"   for entropy > 5.0 (near-random — very likely a real secret)
        "MEDIUM" for entropy 4.5–5.0 (elevated but could be a long identifier)
    """
    return "HIGH" if entropy > 5.0 else "MEDIUM"


def _redact_line(line: str, secret: str) -> str:
    """Replace the secret value in a source line with [REDACTED].

    We never store plaintext credentials in RawFinding.code_snippet.
    Only enough context is retained to identify the file location.

    Args:
        line: The full source line containing the secret.
        secret: The detected secret value to redact.

    Returns:
        Stripped source line with the secret replaced by [REDACTED].
    """
    return line.replace(secret, "[REDACTED]").strip()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class SecretsDetector:
    """Secrets scanner — detect-secrets wrapper with entropy-based regex fallback.

    PIPELINE ORDER: Always instantiate and call scan() FIRST in the scanner
    pipeline (before Bandit, Semgrep, pip-audit). See PIPELINE_PRIORITY = 0.

    Usage::

        detector = SecretsDetector()
        findings = detector.scan(Path("./my-project"))
        # returns list[RawFinding], all with severity="CRITICAL"
    """

    def scan(self, target: Path) -> list[RawFinding]:
        """Run secrets detection on the given target path.

        Tries detect-secrets first. Automatically falls back to the entropy-based
        regex scanner if detect-secrets is not found on PATH.

        Args:
            target: Resolved absolute path (file or directory) to scan.

        Returns:
            List of RawFinding. All detected secrets use severity="CRITICAL".
        """
        if self._detect_secrets_available():
            logger.debug("detect-secrets available — using as primary secrets scanner")
            return self._detect_secrets_scan(target)

        logger.warning(
            "detect-secrets not found on PATH — falling back to entropy-based regex scanner. "
            "Install detect-secrets for higher accuracy: "
            "pip install detect-secrets"
        )
        return self._entropy_scan(target)

    # ------------------------------------------------------------------
    # detect-secrets path
    # ------------------------------------------------------------------

    def _detect_secrets_available(self) -> bool:
        """Return True if detect-secrets is installed and accessible on PATH.

        Returns:
            True if `detect-secrets --version` exits with code 0, False otherwise.
        """
        try:
            result = subprocess.run(
                ["detect-secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _detect_secrets_scan(self, target: Path) -> list[RawFinding]:
        """Run detect-secrets filesystem scanner and parse JSON output.

        Command: ``detect-secrets scan <path>`` (outputs JSON by default)

        Falls back to entropy scan on timeout or unexpected failure.

        Args:
            target: Path to scan (file or directory).

        Returns:
            Parsed list of RawFinding from detect-secrets JSON output.
        """
        try:
            result = subprocess.run(
                [
                    "detect-secrets",
                    "scan",
                    str(target),
                    "--all-files",  # Include non-git-tracked files
                    # Disable high-entropy plugins — they produce massive false-positive
                    # counts on any codebase with SHA hashes, UUIDs, or bcrypt values.
                    "--disable-plugin",
                    "HexHighEntropyString",
                    "--disable-plugin",
                    "Base64HighEntropyString",
                    "--exclude-files",
                    # Skip tool artifact / cache dirs, test dirs, build output, and migrations.
                    # Uses Python regex matched against each file path.
                    r"(\.pytest_cache|\.mypy_cache|\.ruff_cache|__pycache__|node_modules|\.venv|venv|env|\.tox|\.eggs|tests?|test_[^/\\]*|fixtures|build|dist|\.git|migrations|alembic|\.next)[/\\]|[/\\]tests?\.py$|\.sarif$|\.tsbuildinfo$|velonus-results\.json$",
                ],
                capture_output=True,
                text=True,
                timeout=120,  # 2-minute cap — generous for large repos
            )
        except subprocess.TimeoutExpired:
            logger.warning("detect-secrets timed out after 120s — falling back to entropy scanner")
            return self._entropy_scan(target)
        except FileNotFoundError:
            # Handles the edge case where detect-secrets is removed between the
            # availability check and the actual scan run.
            logger.warning("detect-secrets disappeared from PATH — falling back to entropy scanner")
            return self._entropy_scan(target)

        if result.returncode != 0:
            logger.warning(
                "detect-secrets scan failed with exit code %d — falling back to entropy scanner: %s",
                result.returncode,
                result.stderr[:200] if result.stderr else "",
            )
            return self._entropy_scan(target)

        return self._parse_detect_secrets_output(result.stdout, target)

    def _parse_detect_secrets_output(
        self, stdout: str, target: Path | None = None
    ) -> list[RawFinding]:
        """Parse detect-secrets baseline JSON output into RawFinding objects.

        detect-secrets outputs a baseline JSON object with:
          - version: tool version
          - plugins_used: list of detector plugins
          - filters_used: list of filters applied
          - results: dict mapping file paths to list of secrets found
          - generated_at: ISO timestamp

        Each secret in results contains:
          - type: detector name ("AWS Key", "Secret Keyword", etc.)
          - filename: file path
          - hashed_secret: SHA-1 hash (never plaintext)
          - is_verified: bool (whether secret verification passed)
          - line_number: int (1-based line in file)

        Args:
            stdout: Raw stdout string from the detect-secrets subprocess.

        Returns:
            List of RawFinding — one per detected secret.
        """
        findings: list[RawFinding] = []

        try:
            obj: dict[str, Any] = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse detect-secrets JSON output: %s", e)
            return []

        # These types produce excessive false positives: SHA/hex hashes, UUIDs,
        # bcrypt values, and base64-encoded binary data are not usable secrets.
        # We also disable them via --disable-plugin above; this is a second-pass
        # guard for older detect-secrets versions that ignore unknown plugin names.
        _SKIP_TYPES: frozenset[str] = frozenset(
            {
                "Hex High Entropy String",
                "Base64 High Entropy String",
            }
        )

        # Cache each file's lines once — several secrets can share a file, and
        # this is only needed to check for `# velonus: ignore` comments.
        file_lines_cache: dict[str, list[str]] = {}

        def _lines_for(path: str) -> list[str]:
            if path not in file_lines_cache:
                try:
                    from pathlib import Path as _Path2

                    file_lines_cache[path] = (
                        _Path2(path).read_text(encoding="utf-8", errors="replace").splitlines()
                    )
                except OSError:
                    file_lines_cache[path] = []
            return file_lines_cache[path]

        results = obj.get("results", {})
        for file_path, secrets in results.items():
            if not isinstance(secrets, list):
                continue

            # detect-secrets returns paths relative to CWD of the subprocess,
            # which equals the Python process CWD at scan time. The exclusion
            # filter in pipeline.py requires absolute paths (calls relative_to()
            # on them). Resolve here so test/* and other excluded paths are
            # correctly filtered out.
            from pathlib import Path as _Path

            abs_file: str
            p = _Path(file_path)
            # detect-secrets returns paths relative to CWD, not to the scan target;
            # p.resolve() anchors to CWD which is always correct.
            abs_file = str(p) if p.is_absolute() else str(p.resolve())

            # Belt-and-suspenders: skip scanner output / build artifact files even
            # if --exclude-files regex did not filter them (Windows path separator
            # differences can cause regex mismatches).
            _abs_lower = abs_file.lower()
            if (
                _abs_lower.endswith(".sarif")
                or _abs_lower.endswith(".tsbuildinfo")
                or "\\.next\\" in _abs_lower
                or "/.next/" in _abs_lower
            ):
                logger.debug("Skipping build/output artifact file: %s", abs_file)
                continue

            for secret in secrets:
                secret_type = secret.get("type", "unknown")
                if secret_type in _SKIP_TYPES:
                    logger.debug(
                        "Suppressing noisy detect-secrets type: %s in %s", secret_type, abs_file
                    )
                    continue

                line_num = secret.get("line_number", 1)
                rule_id = f"detect-secrets-{secret_type.lower().replace(' ', '-')}"

                file_lines = _lines_for(abs_file)
                line_text = file_lines[line_num - 1] if 0 < line_num <= len(file_lines) else ""
                prev_line = (
                    file_lines[line_num - 2] if 1 < line_num <= len(file_lines) + 1 else None
                )

                findings.append(
                    RawFinding(
                        tool="secrets",
                        rule_id=rule_id,
                        file=abs_file,
                        line=line_num,
                        severity="CRITICAL",
                        message=f"Secret detected [{secret_type}] — rotate immediately",
                        code_snippet="[REDACTED]",
                        metadata={
                            "detector": "detect-secrets",
                            "secret_type": secret_type,
                            "hashed": secret.get("hashed_secret", ""),
                        },
                        suppressed=check_inline_suppression(rule_id, line_text, prev_line),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Entropy-based fallback path
    # ------------------------------------------------------------------

    def _entropy_scan(self, target: Path) -> list[RawFinding]:
        """Entropy-based regex secret scanner — trufflehog fallback.

        Walks the target path recursively, skipping non-code directories and
        binary file extensions. For each source file, applies regex patterns
        for known secret types followed by Shannon entropy thresholding for
        generic high-entropy credential assignments.

        Args:
            target: File or directory to scan.

        Returns:
            List of RawFinding for all detected secrets in the target.
        """
        if target.is_file():
            return self._scan_file(target)

        findings: list[RawFinding] = []
        for file_path in self._iter_files(target):
            findings.extend(self._scan_file(file_path))
        return findings

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Yield scannable source files under root, skipping excluded paths.

        Skipped directories: .git, node_modules, __pycache__, .venv, venv,
                             .env, dist, build, .mypy_cache, .pytest_cache
        Skipped extensions: .pyc, .lock, binary/media formats (see _SKIP_EXTENSIONS)

        Args:
            root: Root directory to walk recursively.

        Yields:
            Path to each file that should be scanned for secrets.
        """
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            # Skip if any parent directory component is in the exclusion set.
            # relative_parts[-1] is the filename itself — only check parent dirs.
            if any(part in _SKIP_DIRS for part in relative_parts[:-1]):
                continue
            if path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            yield path

    def _scan_file(self, path: Path) -> list[RawFinding]:
        """Scan a single file for secrets using pattern matching and entropy.

        Pass 1: Apply each entry in _SECRET_PATTERNS (specific known formats).
        Pass 2: Check generic secret assignments for high Shannon entropy.
                Skips lines already flagged in Pass 1 to avoid duplicates.

        Skips files that cannot be read (binary encoding errors, permissions).

        Args:
            path: Absolute path to the file to scan.

        Returns:
            List of RawFinding for each secret found in the file.
        """
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            logger.debug("Skipping unreadable file %s: %s", path, exc)
            return []

        findings: list[RawFinding] = []
        lines = content.splitlines()
        flagged_lines: set[int] = set()  # prevents double-flagging the same line

        for line_num, line_text in enumerate(lines, start=1):
            prev_line = lines[line_num - 2] if line_num > 1 else None

            # Inline suppression — skip ALL findings on this line when
            # shield:ignore appears on it or on the line immediately above.
            if _is_suppressed(line_text, prev_line):
                continue

            # ----------------------------------------------------------
            # Pass 1: known secret patterns (regex-only, type-specific)
            # ----------------------------------------------------------
            for rule_id, pattern, message in _SECRET_PATTERNS:
                match = pattern.search(line_text)
                if not match:
                    continue

                # group(1) is the captured secret; group(0) is the full match
                secret_value = (
                    match.group(1)
                    if match.lastindex is not None and match.lastindex >= 1
                    else match.group(0)
                )

                # Skip obvious placeholders only for broad/generic patterns.
                # Specific patterns (aws-access-key-id, github-token, etc.) have tight
                # enough regexes that placeholder filtering causes false negatives
                # (e.g. AKIAIOSFODNN7EXAMPLE — the canonical AWS docs example key).
                if rule_id in _HIGH_ENTROPY_REQUIRED and _is_placeholder_value(secret_value):
                    continue

                value_entropy = _shannon_entropy(secret_value)

                # Minimum entropy gate — real secrets are always > 2.5 bits.
                if value_entropy < 2.5:
                    continue

                # Extra entropy gate for broad/generic patterns that fire on
                # env-var references and simple config names (e.g., "$API_KEY").
                if rule_id in _HIGH_ENTROPY_REQUIRED and value_entropy < _MIN_ENTROPY_FOR_GENERIC:
                    continue

                findings.append(
                    RawFinding(
                        tool="secrets",
                        rule_id=rule_id,
                        file=str(path),
                        line=line_num,
                        severity="CRITICAL",
                        message=message,
                        code_snippet=_redact_line(line_text, secret_value),
                        metadata={"entropy": round(value_entropy, 3)},
                        suppressed=check_inline_suppression(rule_id, line_text, prev_line),
                    )
                )
                flagged_lines.add(line_num)

            # ----------------------------------------------------------
            # Pass 2: high-entropy generic assignments (unknown key types)
            # ----------------------------------------------------------
            if line_num in flagged_lines:
                # Already flagged by a specific pattern — skip entropy check
                continue

            assign_match = _ASSIGNMENT_PATTERN.search(line_text)
            if assign_match:
                candidate = assign_match.group(1)

                # Skip placeholder values before computing entropy
                if _is_placeholder_value(candidate):
                    continue

                entropy = _shannon_entropy(candidate)
                if entropy >= _ENTROPY_THRESHOLD:
                    findings.append(
                        RawFinding(
                            tool="secrets",
                            rule_id="high-entropy-secret",
                            file=str(path),
                            line=line_num,
                            severity="CRITICAL",
                            message=(
                                f"High-entropy string in secret assignment "
                                f"(Shannon entropy={entropy:.2f}) — likely a hardcoded credential"
                            ),
                            code_snippet=_redact_line(line_text, candidate),
                            metadata={
                                "entropy": round(entropy, 3),
                                "confidence": _entropy_confidence(entropy),
                            },
                            suppressed=check_inline_suppression(
                                "high-entropy-secret", line_text, prev_line
                            ),
                        )
                    )
                    flagged_lines.add(line_num)

        return findings
