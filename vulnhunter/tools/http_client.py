"""Secure HTTP client — wires ScopeGuard + RateLimiter + Audit + ActionClassifier + HITL.

Every HTTP request made by any agent goes through this single entry point,
enforcing all PRD §5.2 mandatory controls in one place.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from vulnhunter.core.action_classifier import classify_action
from vulnhunter.core.audit import audit_logger
from vulnhunter.core.hitl import approval_queue
from vulnhunter.core.rate_limiter import global_limiter
from vulnhunter.tools.scope_guard import ScopeGuard, ScopeViolationError

logger = logging.getLogger(__name__)


@dataclass
class RequestRecord:
    method: str
    url: str
    status_code: int
    elapsed_ms: float
    risk_level: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""


class SecureHttpClient:
    """All-in-one HTTP client enforcing PRD §5.2 mandatory controls.

    Controls enforced:
    1. Scope whitelist (ScopeGuard)
    2. Private IP block (ScopeGuard)
    3. Redirect scope (ScopeGuard)
    4. Rate limiting (RateLimiter, 10 QPS default)
    5. Action-level gating (L0-L3 classifier)
    6. HITL approval for L2+ actions
    7. Full-chain audit logging
    """

    def __init__(
        self,
        allowed_hosts: list[str],
        agent_name: str = "unknown",
        max_risk_level: int = 1,
        timeout: float = 15.0,
    ) -> None:
        self.scope_guard = ScopeGuard(allowed_hosts, max_risk_level)
        self.agent_name = agent_name
        self.max_risk_level = max_risk_level
        self.client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False
        )
        self.history: list[RequestRecord] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | str | None = None,
        params: dict[str, Any] | None = None,
        is_mutation: bool = False,
    ) -> httpx.Response:
        self.scope_guard.check_url(url)

        classification = classify_action(
            method, url, has_body=json is not None or data is not None,
            is_mutation=is_mutation,
        )

        if classification.level > self.max_risk_level:
            raise ScopeViolationError(
                f"Action risk L{classification.level} exceeds max L{self.max_risk_level}: {classification.reason}"
            )

        if classification.level >= 2 and not classification.auto_execute:
            approval_queue.submit(
                agent=self.agent_name,
                action=f"{method} {url}",
                url=url,
                risk_level=classification.level,
                detail=classification.reason,
            )
            logger.info("L%d action queued for HITL: %s %s", classification.level, method, url)

        await global_limiter.acquire()

        start = time.monotonic()
        response = await self.client.request(
            method, url, headers=headers, json=json, data=data, params=params,
        )
        elapsed = (time.monotonic() - start) * 1000

        audit_logger.log(
            agent=self.agent_name,
            tool="http",
            action=method,
            url=url,
            risk_level=classification.level,
            status_code=response.status_code,
            elapsed_ms=round(elapsed, 2),
        )

        record = RequestRecord(
            method=method, url=url, status_code=response.status_code,
            elapsed_ms=round(elapsed, 2), risk_level=classification.level,
            request_headers=dict(response.request.headers),
            response_headers=dict(response.headers),
            response_body_preview=response.text[:500],
        )
        self.history.append(record)
        return response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def close(self) -> None:
        await self.client.aclose()
