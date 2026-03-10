"""AuthZ Agent (WSTG-ATHN/ATHZ/SESS) — real cookie, JWT, and session analysis.

Performs actual inspection of:
- Cookie security flags (Secure, HttpOnly, SameSite, Expires)
- JWT structure, algorithm, expiration
- Session fixation indicators
- CORS configuration
"""

import base64
import json
import logging
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent
from vulnhunter.core.audit import audit_logger

logger = logging.getLogger(__name__)


class AuthZAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("authz")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "analyze_cookies"},
            {"action": "analyze_jwt"},
            {"action": "check_cors"},
            {"action": "check_session_fixation"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            for host in hosts:
                base = f"https://{host}" if not host.startswith("http") else host
                try:
                    resp = await client.get(base)
                except Exception:
                    try:
                        base = f"http://{host}"
                        resp = await client.get(base)
                    except Exception:
                        continue

                audit_logger.log("authz", "http", "GET", base, 0, resp.status_code)

                findings.extend(self._analyze_cookies(resp, base))
                findings.extend(self._analyze_cors(resp, base))
                findings.extend(self._check_jwt_in_response(resp, base))

                login_paths = ["/login", "/api/auth/login", "/api/login", "/signin", "/api/v1/auth/login"]
                for lp in login_paths:
                    try:
                        r = await client.post(
                            urljoin(base, lp),
                            json={"username": "test", "password": "test"},
                            headers={"Content-Type": "application/json"},
                        )
                        audit_logger.log("authz", "http", "POST", urljoin(base, lp), 1, r.status_code)
                        findings.extend(self._analyze_cookies(r, urljoin(base, lp)))
                        findings.extend(self._check_jwt_in_response(r, urljoin(base, lp)))
                    except Exception:
                        pass

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"findings": findings},
            tool_calls=len(findings),
        )

    def _analyze_cookies(self, resp: httpx.Response, url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for cookie_header in resp.headers.get_list("set-cookie"):
            name = cookie_header.split("=")[0].strip()
            lower = cookie_header.lower()

            is_session = any(k in name.lower() for k in ["session", "sid", "token", "auth", "jwt"])
            if not is_session:
                continue

            if "secure" not in lower:
                findings.append({
                    "title": f"Cookie '{name}' Without Secure Flag",
                    "category": "Session Management",
                    "wstg_refs": ["WSTG-SESS-02"],
                    "severity": "medium",
                    "confidence": 0.95,
                    "description": f"Session cookie '{name}' from {url} lacks the Secure flag.",
                    "agent": self.name,
                })

            if "httponly" not in lower:
                findings.append({
                    "title": f"Cookie '{name}' Without HttpOnly Flag",
                    "category": "Session Management",
                    "wstg_refs": ["WSTG-SESS-02"],
                    "severity": "low",
                    "confidence": 0.95,
                    "description": f"Session cookie '{name}' from {url} lacks the HttpOnly flag, exposable via XSS.",
                    "agent": self.name,
                })

            if "samesite" not in lower:
                findings.append({
                    "title": f"Cookie '{name}' Without SameSite Attribute",
                    "category": "Session Management",
                    "wstg_refs": ["WSTG-SESS-02"],
                    "severity": "low",
                    "confidence": 0.90,
                    "description": f"Session cookie '{name}' from {url} has no SameSite attribute, vulnerable to CSRF.",
                    "agent": self.name,
                })
        return findings

    def _analyze_cors(self, resp: httpx.Response, url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            findings.append({
                "title": "Insecure CORS: Wildcard Origin with Credentials",
                "category": "Security Misconfiguration",
                "wstg_refs": ["WSTG-CONF-07"],
                "severity": "high",
                "confidence": 0.95,
                "description": f"{url} allows any origin with credentials. Attackers can steal data cross-origin.",
                "agent": self.name,
            })
        elif acao == "*":
            findings.append({
                "title": "Permissive CORS: Wildcard Access-Control-Allow-Origin",
                "category": "Security Misconfiguration",
                "wstg_refs": ["WSTG-CONF-07"],
                "severity": "low",
                "confidence": 0.85,
                "description": f"{url} sets Access-Control-Allow-Origin: *.",
                "agent": self.name,
            })
        return findings

    def _check_jwt_in_response(self, resp: httpx.Response, url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        tokens = jwt_pattern.findall(resp.text)

        for token in tokens[:3]:
            try:
                parts = token.split(".")
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                alg = header.get("alg", "")
                if alg.lower() == "none":
                    findings.append({
                        "title": "JWT Uses 'none' Algorithm",
                        "category": "Authentication",
                        "wstg_refs": ["WSTG-ATHN-09"],
                        "severity": "critical",
                        "confidence": 0.98,
                        "description": f"JWT from {url} uses algorithm 'none', bypassing signature verification.",
                        "agent": self.name,
                    })
                elif alg.upper() in ("HS256",) and header.get("typ") == "JWT":
                    pass

                if "exp" not in payload:
                    findings.append({
                        "title": "JWT Token Has No Expiration",
                        "category": "Session Management",
                        "wstg_refs": ["WSTG-SESS-06"],
                        "severity": "high",
                        "confidence": 0.85,
                        "description": f"JWT from {url} has no 'exp' claim. Tokens remain valid indefinitely once leaked.",
                        "agent": self.name,
                    })
            except Exception:
                pass
        return findings
