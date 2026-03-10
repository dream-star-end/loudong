"""BizLogic Agent (WSTG-BUSL) — business logic flow analysis via SecureHttpClient."""

import logging
from typing import Any
from urllib.parse import urljoin

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent

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
        return [{"action": "check_rate_limiting"}, {"action": "check_method_override"}]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        routes = context.get("routes", [])
        findings: list[dict[str, Any]] = []

        client = self.create_http_client(hosts)
        try:
            for host in hosts:
                base = f"https://{host}" if not host.startswith("http") else host

                endpoints_to_test = list(SENSITIVE_ENDPOINTS)
                for r in routes:
                    path = r.get("path", "")
                    if any(kw in path.lower() for kw in ["login", "register", "auth", "password"]) and path not in endpoints_to_test:
                        endpoints_to_test.append(path)

                for endpoint in endpoints_to_test:
                    url = urljoin(base, endpoint)
                    try:
                        r_test = await client.post(url, json={"username": "test", "password": "wrong"})
                        if r_test.status_code in (404, 405):
                            continue
                    except Exception:
                        continue

                    success_count = 0
                    for i in range(6):
                        try:
                            r = await client.post(url, json={"username": f"rl_test_{i}", "password": "wrong"})
                            if r.status_code != 429:
                                success_count += 1
                        except Exception:
                            break
                    if success_count >= 5:
                        findings.append({
                            "title": f"No Rate Limiting on {endpoint}", "category": "Business Logic",
                            "wstg_refs": ["WSTG-BUSL-05"], "severity": "medium", "confidence": 0.85,
                            "description": f"Endpoint {url} accepted {success_count} rapid requests without 429.",
                            "agent": self.name,
                        })
        finally:
            await client.close()

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            outputs={"findings": findings}, tool_calls=len(client.history),
        )
