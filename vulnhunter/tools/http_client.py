"""Audited HTTP client — every request is logged and scope-checked."""

import logging
import time
from dataclasses import dataclass, field

import httpx

from vulnhunter.tools.scope_guard import ScopeGuard

logger = logging.getLogger(__name__)


@dataclass
class RequestRecord:
    method: str
    url: str
    status_code: int
    elapsed_ms: float
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""


class AuditedHttpClient:
    """HTTP client that enforces scope and logs every request."""

    def __init__(self, scope_guard: ScopeGuard, timeout: float = 30.0) -> None:
        self.scope_guard = scope_guard
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self.history: list[RequestRecord] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict | None = None,  # type: ignore[type-arg]
        data: str | None = None,
    ) -> httpx.Response:
        self.scope_guard.check_url(url)

        start = time.monotonic()
        response = await self.client.request(
            method, url, headers=headers, json=json, content=data
        )
        elapsed = (time.monotonic() - start) * 1000

        record = RequestRecord(
            method=method,
            url=url,
            status_code=response.status_code,
            elapsed_ms=round(elapsed, 2),
            request_headers=dict(response.request.headers),
            response_headers=dict(response.headers),
            response_body_preview=response.text[:500],
        )
        self.history.append(record)
        logger.debug(
            "%s %s -> %d (%.1fms)", method, url, response.status_code, elapsed
        )
        return response

    async def get(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    async def post(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("POST", url, **kwargs)  # type: ignore[arg-type]

    async def close(self) -> None:
        await self.client.aclose()
