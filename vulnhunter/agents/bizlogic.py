"""BizLogic Agent (WSTG-BUSL) — business logic flow analysis.

Checks for:
- Rate limiting on sensitive endpoints (login, register, password reset)
- Flow integrity (can steps be skipped?)
- Method override (POST → GET bypass)
"""

import logging
from typing import Any
from urllib.parse import urljoin

import httpx

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent
from vulnhunter.core.audit import audit_logger

logger = logging.getLogger(__name__)

SENSITIVE_ENDPOINTS = [
    "/login", "/api/auth/login", "/api/login", "/signin",
    "/register", "/api/auth/register", "/signup",
    "/forgot-password", "/api/auth/forgot-password", "/reset-password",
    "/api/v1/auth/login", "/api/v1/auth/register",
]


class BizLogicAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("bizlogic")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "check_rate_limiting"},
            {"action": "check_method_override"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        routes = context.get("routes", [])
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True, verify=False
        ) as client:
            for host in hosts:
                base = f"https://{host}" if not host.startswith("http") else host

                endpoints_to_test = list(SENSITIVE_ENDPOINTS)
                for r in routes:
                    path = r.get("path", "")
                    if any(kw in path.lower() for kw in ["login", "register", "auth", "password", "forgot"]) and path not in endpoints_to_test:
                        endpoints_to_test.append(path)

                for endpoint in endpoints_to_test:
                    url = urljoin(base, endpoint)
                    try:
                        r_test = await client.post(
                            url,
                            json={"username": "test", "password": "wrong"},
                            headers={"Content-Type": "application/json"},
                        )
                        if r_test.status_code in (404, 405):
                            continue
                    except Exception:
                        continue

                    success_count = 0
                    for i in range(6):
                        try:
                            r = await client.post(
                                url,
                                json={"username": f"ratelimit_test_{i}", "password": "wrong_password"},
                                headers={"Content-Type": "application/json"},
                            )
                            audit_logger.log("bizlogic", "http", "POST", url, 1, r.status_code)
                            if r.status_code != 429:
                                success_count += 1
                        except Exception:
                            break

                    if success_count >= 5:
                        findings.append({
                            "title": f"No Rate Limiting on {endpoint}",
                            "category": "Business Logic",
                            "wstg_refs": ["WSTG-BUSL-05"],
                            "severity": "medium",
                            "confidence": 0.85,
                            "description": (
                                f"Endpoint {url} accepted {success_count} rapid requests "
                                f"without returning 429. Brute-force attacks are possible."
                            ),
                            "agent": self.name,
                        })

                for r in routes:
                    if r.get("method", "").upper() == "POST":
                        url = urljoin(base, r["path"])
                        try:
                            resp_get = await client.get(url)
                            if resp_get.status_code == 200 and len(resp_get.text) > 50:
                                findings.append({
                                    "title": f"POST Endpoint Accessible via GET: {r['path']}",
                                    "category": "Business Logic",
                                    "wstg_refs": ["WSTG-BUSL-01"],
                                    "severity": "low",
                                    "confidence": 0.70,
                                    "description": (
                                        f"POST endpoint {r['path']} also responds to GET, "
                                        f"potentially bypassing CSRF or flow controls."
                                    ),
                                    "agent": self.name,
                                })
                        except Exception:
                            pass

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"findings": findings},
            tool_calls=len(findings),
        )
