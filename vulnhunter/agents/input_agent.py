"""Input Agent (WSTG-INPV) — parameter discovery + safe injection probing via SecureHttpClient."""

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent

logger = logging.getLogger(__name__)

XSS_PROBE = "<vh_xss_test>"
SQLI_PROBES = ["'", "1' OR '1'='1"]
SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_", r"ORA-\d{5}", r"PostgreSQL.*ERROR",
    r"SQLite3::", r"Microsoft SQL", r"unclosed quotation",
    r"syntax error at or near", r"pg_query",
]


class InputAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("input")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "enumerate_input_points"},
            {"action": "probe_xss_reflection"},
            {"action": "probe_sqli_errors"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        forms = context.get("forms", [])
        routes = context.get("routes", [])
        findings: list[dict[str, Any]] = []
        input_points: list[dict[str, Any]] = []

        for form in forms:
            for inp in form.get("inputs", []):
                input_points.append({
                    "page": form["page"], "action": form["action"], "method": form["method"],
                    "param_name": inp["name"], "param_type": inp["type"], "source": "form",
                })
        for route in routes:
            qs = parse_qs(urlparse(route.get("path", "")).query)
            for param in qs:
                input_points.append({
                    "path": route["path"], "method": route.get("method", "GET"),
                    "param_name": param, "param_type": "query", "source": "url",
                })

        client = self.create_http_client(hosts)
        try:
            for host in hosts:
                base = f"https://{host}" if not host.startswith("http") else host
                probe_targets: list[tuple[str, str, str]] = []
                for form in forms:
                    for inp in form.get("inputs", []):
                        probe_targets.append((form["action"], inp["name"], form["method"]))
                for route in routes:
                    path = route.get("path", "")
                    if "?" in path:
                        for param in parse_qs(urlparse(path).query):
                            probe_targets.append((urljoin(base, path.split("?")[0]), param, "GET"))

                tested: set[str] = set()
                for action_url, param_name, method in probe_targets[:20]:
                    key = f"{method}:{action_url}:{param_name}"
                    if key in tested:
                        continue
                    tested.add(key)
                    if not action_url.startswith("http"):
                        action_url = urljoin(base, action_url)

                    try:
                        if method.upper() == "GET":
                            r = await client.get(action_url, params={param_name: XSS_PROBE})
                        else:
                            r = await client.post(action_url, data={param_name: XSS_PROBE})
                        if XSS_PROBE in r.text:
                            findings.append({
                                "title": f"Reflected Input in Parameter '{param_name}'",
                                "category": "Input Validation", "wstg_refs": ["WSTG-INPV-01"],
                                "severity": "high", "confidence": 0.85,
                                "description": f"Parameter '{param_name}' at {action_url} reflects input without encoding.",
                                "agent": self.name,
                            })
                    except Exception:
                        pass

                    for sqli_probe in SQLI_PROBES[:1]:
                        try:
                            if method.upper() == "GET":
                                r = await client.get(action_url, params={param_name: sqli_probe})
                            else:
                                r = await client.post(action_url, data={param_name: sqli_probe})
                            for pattern in SQL_ERROR_PATTERNS:
                                if re.search(pattern, r.text, re.IGNORECASE):
                                    findings.append({
                                        "title": f"SQL Error Triggered via Parameter '{param_name}'",
                                        "category": "Input Validation", "wstg_refs": ["WSTG-INPV-05"],
                                        "severity": "high", "confidence": 0.80,
                                        "description": f"SQL error detected probing '{param_name}' at {action_url}.",
                                        "agent": self.name,
                                    })
                                    break
                        except Exception:
                            pass
        finally:
            await client.close()

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            outputs={"findings": findings, "input_points": input_points},
            tool_calls=len(client.history),
        )
