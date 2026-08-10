"""Velonus API client — synchronous httpx wrapper for the backend API.

All methods raise ``APIError`` on non-2xx responses so callers can catch a
single exception type. Connection failures (timeout, DNS, etc.) are wrapped
in ``APIConnectionError`` for a better user-facing message.

Usage::

    from shield.core.api_client import VelonusClient, APIError, APIConnectionError

    client = VelonusClient(api_key="vn_sk_...", api_url="https://velonus-production.up.railway.app")
    try:
        scan = client.create_scan("/path/to/project", [])
        print(scan["scan_id"])
    except APIConnectionError:
        print("Cannot reach the Velonus API — check your connection.")
    except APIError as e:
        print(f"API error {e.status_code}: {e.message}")

Design decisions:
- Synchronous httpx.Client — the CLI is not an async application; asyncio is
  only used inside scan.py to drive the pipeline, not at the command level.
- Timeout: 10s for health/auth, 30s for scan submission, 10s for polling.
- All requests send ``Authorization: Bearer <api_key>`` regardless of endpoint.
- 401 → APIError with a hint to run ``velonus auth login``.
- 501 → APIError; caller should degrade gracefully (API not yet wired).
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

# Narrow query-param type compatible with httpx's accepted param types.
type _QueryScalar = str | int | float | bool | None
type _QueryValue = _QueryScalar | Sequence[_QueryScalar]
type _QueryParams = dict[str, _QueryValue]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class APIError(Exception):
    """Non-2xx response from the Velonus API."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class APIConnectionError(Exception):
    """Failed to reach the Velonus API (network / DNS / timeout)."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class VelonusClient:
    """Synchronous Velonus API client backed by httpx.

    Args:
        api_key: Velonus API key (stored in ~/.velonus/config.toml).
        api_url: Base URL of the Velonus API (no trailing slash).
    """

    def __init__(self, api_key: str, api_url: str) -> None:
        self._api_key = api_key
        self._base_url = api_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "velonus-cli/1.0",
        }

    # ---------------------------------------------------------------------- #
    # Connectivity
    # ---------------------------------------------------------------------- #

    def health(self) -> bool:
        """Return True if the API is reachable and healthy.

        Calls ``GET /health`` which is auth-exempt. Used during ``auth login``
        to verify the API URL is correct before saving credentials.

        Returns:
            True on HTTP 200 with ``{"status": "ok"}``.

        Raises:
            APIConnectionError: API is unreachable (timeout, DNS failure, etc.).
        """
        try:
            resp = httpx.get(
                f"{self._base_url}/health",
                timeout=10.0,
            )
            return resp.status_code == 200
        except httpx.RequestError as exc:
            raise APIConnectionError(str(exc)) from exc

    def validate_key(self) -> bool:
        """Return True if the stored API key is accepted by the server.

        Calls ``GET /v1/orgs/me`` which requires a valid Bearer token.
        Returns False on 401 (invalid/expired key).

        Raises:
            APIConnectionError: API is unreachable.
        """
        try:
            resp = httpx.get(
                f"{self._base_url}/v1/orgs/me",
                headers=self._headers,
                timeout=10.0,
            )
            return resp.status_code != 401
        except httpx.RequestError as exc:
            raise APIConnectionError(str(exc)) from exc

    # ---------------------------------------------------------------------- #
    # Scans
    # ---------------------------------------------------------------------- #

    def create_scan(
        self,
        target_path: str,
        exclude_patterns: list[str] | None = None,
    ) -> dict[str, object]:
        """Submit a new scan job to the API (server-side rescan).

        Prefer ``upload_scan`` for CLI usage — this endpoint asks the server
        to re-scan a path, which only works when the path is accessible on the
        server (not useful for local CLI scans against a developer's machine).

        Args:
            target_path: Absolute path to the directory to scan.
            exclude_patterns: Optional glob patterns to exclude.

        Returns:
            Dict with at least ``scan_id`` (str) and ``status`` (str).

        Raises:
            APIError: Non-2xx response (e.g. 501 if API not yet wired).
            APIConnectionError: API unreachable.
        """
        payload: dict[str, object] = {
            "target_path": target_path,
            "exclude_patterns": exclude_patterns or [],
        }
        return self._post("/v1/scans", payload)

    def upload_scan(
        self,
        target_path: str,
        findings: list[object],
        exclude_patterns: list[str] | None = None,
        source_contexts: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Upload locally-scanned findings to the API for AI triage.

        The CLI runs the scanner pipeline locally and calls this endpoint to
        upload the resulting findings.  The server stores them and queues AI
        triage without re-scanning (the local path is not accessible on the
        server).

        Args:
            target_path: Local path that was scanned (stored for display only).
            findings: List of NormalizedFinding objects from the local pipeline.
            exclude_patterns: Glob patterns used during the local scan.
            source_contexts: Optional dict mapping finding fingerprint (id) to
                up to 40 surrounding source lines. Stored server-side so the AI
                triage engine has file-level context even for local-only projects.

        Returns:
            Dict with ``scan_id`` and ``status`` ("running").

        Raises:
            APIError: Non-2xx response.
            APIConnectionError: API unreachable.
        """
        contexts = source_contexts or {}
        payload: dict[str, object] = {
            "target_path": target_path,
            "exclude_patterns": exclude_patterns or [],
            "findings": [
                self._serialize_finding(f, contexts.get(getattr(f, "id", ""), "")) for f in findings
            ],
        }
        # Use a longer timeout — payload can be several KB with code snippets.
        return self._post("/v1/scans/ingest", payload, timeout=60.0)

    @staticmethod
    def _serialize_finding(f: object, source_context: str = "") -> dict[str, object]:
        """Convert a NormalizedFinding dataclass to a JSON-serialisable dict."""
        return {
            "fingerprint": getattr(f, "id", ""),  # NormalizedFinding.id is the fingerprint
            "tool": getattr(f, "tool", ""),
            "rule_id": getattr(f, "rule_id", ""),
            "severity": str(getattr(f, "severity", "")),
            "confidence": str(getattr(f, "confidence", "")),
            "file_path": getattr(f, "file", ""),
            "line_start": getattr(f, "line_start", 0),
            "line_end": getattr(f, "line_end", 0),
            "code_snippet": getattr(f, "code_snippet", "") or "",
            "message": getattr(f, "message", ""),
            "cwe": list(getattr(f, "cwe", [])),
            "owasp": list(getattr(f, "owasp", [])),
            "fix_available": bool(getattr(f, "fix_available", False)),
            "source_context": source_context,
            "suppressed": bool(getattr(f, "suppressed", False)),
        }

    def get_scan(self, scan_id: str) -> dict[str, object]:
        """Poll the status and summary of an existing scan.

        Args:
            scan_id: UUID returned by ``create_scan()``.

        Returns:
            Dict with ``status`` (pending|running|complete|failed),
            ``finding_count``, ``critical_count``, ``high_count``, etc.

        Raises:
            APIError: Non-2xx response.
            APIConnectionError: API unreachable.
        """
        return self._get(f"/v1/scans/{scan_id}")

    def get_findings(
        self,
        scan_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """Fetch paginated findings for a completed scan.

        Args:
            scan_id: UUID of the scan to fetch findings for.
            limit: Max findings per page (default 100).
            offset: Pagination offset (default 0).

        Returns:
            List of finding dicts with AI-enriched fields when available.

        Raises:
            APIError: Non-2xx response.
            APIConnectionError: API unreachable.
        """
        result = self._get(
            f"/v1/scans/{scan_id}/findings",
            params={"limit": limit, "offset": offset},
        )
        # API returns either a list directly or a dict with a "findings" key.
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        raw = result.get("findings", [])
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        return []

    def request_remediation(self, finding_id: str) -> dict[str, object]:
        """Trigger AI fix generation for a single finding.

        Enqueues a RemediationEngine job for the given finding.
        Results are written to the finding's ``ai_remediation`` field
        and can be retrieved via ``get_findings()``.

        Args:
            finding_id: UUID of the finding to remediate.

        Returns:
            Dict with ``status`` and ``finding_id``.

        Raises:
            APIError: Non-2xx response.
            APIConnectionError: API unreachable.
        """
        return self._post(f"/v1/findings/{finding_id}/remediation", {})

    # ---------------------------------------------------------------------- #
    # GitHub PR review
    # ---------------------------------------------------------------------- #

    def review_pr(self, owner: str, repo: str, pr_number: int) -> dict[str, object]:
        """Trigger an on-demand security review of a GitHub pull request.

        Backs ``velonus pr review <pr_url>``. Runs synchronously server-side —
        posts inline review comments + a check run to GitHub and returns a
        findings summary directly (no polling; there is no scan_id for this).

        Args:
            owner: Repository owner login (org or user).
            repo: Repository name.
            pr_number: Pull request number.

        Returns:
            Dict with ``finding_count``, ``critical_count``, ``high_count``,
            ``conclusion``, or ``status: "skipped"`` if the GitHub App isn't
            configured server-side.

        Raises:
            APIError: Non-2xx response (e.g. 404 if no installation is linked
                for this owner).
            APIConnectionError: API unreachable.
        """
        # PR reviews scan and download files server-side — allow more time
        # than the default 30s used for scan submission.
        return self._post(
            "/v1/github/pr-review",
            {"owner": owner, "repo": repo, "pr_number": pr_number},
            timeout=90.0,
        )

    # ---------------------------------------------------------------------- #
    # CI/CD
    # ---------------------------------------------------------------------- #

    def get_ci_template(self, provider: str = "github-actions") -> dict[str, object]:
        """Fetch a ready-to-use CI workflow that runs `velonus scan --ai` in CI.

        Backs ``velonus ci --generate-workflow``.

        Args:
            provider: CI provider to generate a workflow for. Only
                "github-actions" exists server-side today.

        Returns:
            Dict with ``provider``, ``filename`` (suggested relative path),
            and ``content`` (the workflow file text).

        Raises:
            APIError: Non-2xx response (e.g. 422 for an unsupported provider).
            APIConnectionError: API unreachable.
        """
        return self._get("/v1/orgs/me/ci-template", params={"provider": provider})

    # ---------------------------------------------------------------------- #
    # Internal HTTP helpers
    # ---------------------------------------------------------------------- #

    def _get(
        self,
        path: str,
        *,
        params: _QueryParams | None = None,
        timeout: float = 10.0,
    ) -> dict[str, object]:
        try:
            resp = httpx.get(
                f"{self._base_url}{path}",
                headers=self._headers,
                params=params,
                timeout=timeout,
            )
        except httpx.RequestError as exc:
            raise APIConnectionError(str(exc)) from exc
        return self._handle(resp)

    def _post(
        self,
        path: str,
        payload: dict[str, object],
        *,
        timeout: float = 30.0,
    ) -> dict[str, object]:
        try:
            resp = httpx.post(
                f"{self._base_url}{path}",
                headers=self._headers,
                json=payload,
                timeout=timeout,
            )
        except httpx.RequestError as exc:
            raise APIConnectionError(str(exc)) from exc
        return self._handle(resp)

    @staticmethod
    def _handle(resp: httpx.Response) -> dict[str, object]:
        """Raise ``APIError`` for non-2xx responses; return parsed JSON."""
        if resp.is_success:
            try:
                return resp.json()  # type: ignore[no-any-return]
            except Exception:  # noqa: BLE001
                return {"raw": resp.text}
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:  # noqa: BLE001
            detail = resp.text
        raise APIError(resp.status_code, str(detail))


# ---------------------------------------------------------------------------
# Factory — create from stored config
# ---------------------------------------------------------------------------


def client_from_config() -> VelonusClient | None:
    """Create a VelonusClient from the stored CLI config.

    Returns None when no API key is configured, so callers can check
    with a simple ``if client:`` guard.

    Usage::

        from shield.core.api_client import client_from_config

        client = client_from_config()
        if client is None:
            console.print("[yellow]Run 'velonus auth login' to enable AI features.[/yellow]")
            return
    """
    from shield.core import config as cfg  # noqa: PLC0415 — avoid circular import at module level

    api_key = cfg.get_api_key()
    if not api_key:
        return None
    return VelonusClient(api_key=api_key, api_url=cfg.get_api_url())
