"""Minimal async client for the NVD CVE API 2.0."""

from __future__ import annotations

import asyncio
from datetime import datetime
import logging
import time
from typing import Any
from urllib.parse import quote, urlencode

from aiohttp import ClientError, ClientSession, ClientTimeout
from yarl import URL

from .const import (
    NVD_CVE_API_URL,
    NVD_DELAY_WITH_KEY,
    NVD_DELAY_WITHOUT_KEY,
    NVD_REQUEST_TIMEOUT,
    NVD_RESULTS_PER_PAGE,
)

_LOGGER = logging.getLogger(__name__)

USER_AGENT = "HomeAssistant-CitrixSecurityBulletins/1.0"


class NvdError(Exception):
    """Generic NVD API error."""


class NvdAuthError(NvdError):
    """The API key was rejected."""


class NvdRateLimitError(NvdError):
    """NVD rate limit hit or service busy."""


def _format_datetime(value: datetime) -> str:
    """Format a datetime as ISO-8601 with UTC offset, as expected by NVD."""
    return value.isoformat(timespec="milliseconds")


class NvdClient:
    """Client for https://services.nvd.nist.gov/rest/json/cves/2.0."""

    def __init__(self, session: ClientSession, api_key: str | None = None) -> None:
        """Initialize the client."""
        self._session = session
        self._api_key = api_key or None
        self._delay = NVD_DELAY_WITH_KEY if self._api_key else NVD_DELAY_WITHOUT_KEY
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self) -> None:
        """Respect the NVD rate limit between consecutive requests."""
        wait = self._last_request + self._delay - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()

    async def _request(self, params: dict[str, Any], flags: list[str]) -> dict[str, Any]:
        """Perform a single API request."""
        # Build the query ourselves so '+' and ':' are encoded exactly once.
        query = urlencode(params, quote_via=quote, safe=":")
        if flags:
            query = "&".join([query, *flags]) if query else "&".join(flags)
        url = URL(f"{NVD_CVE_API_URL}?{query}", encoded=True)

        headers = {"User-Agent": USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key

        async with self._lock:
            await self._throttle()
            try:
                async with self._session.get(
                    url, headers=headers, timeout=ClientTimeout(total=NVD_REQUEST_TIMEOUT)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    message = resp.headers.get("message", "")
                    _LOGGER.warning(
                        "NVD returned HTTP %s (message: %s, api key used: %s) for %s",
                        resp.status,
                        message or "-",
                        bool(self._api_key),
                        url.path,
                    )
                    if self._api_key and (
                        resp.status == 401 or "apikey" in message.lower()
                    ):
                        raise NvdAuthError(message or f"HTTP {resp.status}")
                    if resp.status in (403, 429, 503):
                        raise NvdRateLimitError(f"HTTP {resp.status} {message}".strip())
                    raise NvdError(f"HTTP {resp.status} {message}".strip())
            except TimeoutError as err:
                raise NvdError("Timeout while contacting the NVD API") from err
            except ClientError as err:
                raise NvdError(f"Error while contacting the NVD API: {err}") from err

    async def async_get_cves(
        self,
        cpe_match: str | None = None,
        last_mod_start: datetime | None = None,
        last_mod_end: datetime | None = None,
        source_identifier: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all CVEs matching a CPE or a source (CNA).

        Optionally limited to CVEs modified within a range of at most 120 days.
        """
        params: dict[str, Any] = {"resultsPerPage": NVD_RESULTS_PER_PAGE}
        if cpe_match:
            params["virtualMatchString"] = cpe_match
        if source_identifier:
            params["sourceIdentifier"] = source_identifier
        flags: list[str] = []
        if last_mod_start and last_mod_end:
            params["lastModStartDate"] = _format_datetime(last_mod_start)
            params["lastModEndDate"] = _format_datetime(last_mod_end)
        else:
            # Full load: rejected CVEs are irrelevant.
            flags.append("noRejected")

        items: list[dict[str, Any]] = []
        start_index = 0
        while True:
            data = await self._request({**params, "startIndex": start_index}, flags)
            page: list[dict[str, Any]] = data.get("vulnerabilities", [])
            items.extend(page)
            total = int(data.get("totalResults", 0))
            start_index += int(data.get("resultsPerPage", len(page)) or len(page))
            if not page or start_index >= total:
                return items

    async def async_validate(self) -> None:
        """Perform a minimal request to validate connectivity and API key."""
        await self._request({"resultsPerPage": 1}, [])
