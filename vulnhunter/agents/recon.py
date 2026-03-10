"""Recon Agent (WSTG-INFO) — real HTTP-based asset discovery and fingerprinting.

Performs actual requests to analyze:
- HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Server/framework fingerprinting (Server, X-Powered-By, X-AspNet-Version)
- robots.txt and sitemap.xml parsing
- OpenAPI/Swagger endpoint discovery
- Error page information leakage
"""

import logging
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent
from vulnhunter.core.audit import audit_logger

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "strict-transport-security": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing HTTP Strict-Transport-Security Header",
        "severity": "medium",
    },
    "content-security-policy": {
        "wstg": "WSTG-CONF-12",
        "title": "Missing Content-Security-Policy Header",
        "severity": "medium",
    },
    "x-frame-options": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing X-Frame-Options Header",
        "severity": "low",
    },
    "x-content-type-options": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "low",
    },
    "x-xss-protection": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing X-XSS-Protection Header",
        "severity": "info",
    },
    "referrer-policy": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing Referrer-Policy Header",
        "severity": "info",
    },
    "permissions-policy": {
        "wstg": "WSTG-CONF-07",
        "title": "Missing Permissions-Policy Header",
        "severity": "info",
    },
}

FINGERPRINT_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/docs", "/redoc",
]


class ReconAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("recon")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        hosts = context.get("allowed_hosts", [])
        return [
            {"action": "check_security_headers", "hosts": hosts},
            {"action": "fingerprint_server", "hosts": hosts},
            {"action": "fetch_robots_sitemap", "hosts": hosts},
            {"action": "discover_api_specs", "hosts": hosts},
            {"action": "check_error_pages", "hosts": hosts},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        findings: list[dict[str, Any]] = []
        asset_inventory: list[dict[str, Any]] = []
        routes: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            for host in hosts:
                base = f"https://{host}" if not host.startswith("http") else host
                try:
                    resp = await client.get(base)
                except Exception as e:
                    try:
                        base = f"http://{host}" if not host.startswith("http") else host
                        resp = await client.get(base)
                    except Exception:
                        self.logger.warning("Cannot reach %s: %s", host, e)
                        continue

                audit_logger.log("recon", "http", "GET", base, 0, resp.status_code)

                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                for hdr, info in SECURITY_HEADERS.items():
                    if hdr not in headers_lower:
                        findings.append({
                            "title": info["title"],
                            "category": "Security Misconfiguration",
                            "wstg_refs": [info["wstg"]],
                            "severity": info["severity"],
                            "confidence": 0.95,
                            "description": f"The response from {base} does not include the '{hdr}' header.",
                            "agent": self.name,
                        })

                fingerprints: dict[str, str] = {}
                for fh in FINGERPRINT_HEADERS:
                    if fh in headers_lower:
                        fingerprints[fh] = headers_lower[fh]

                if fingerprints:
                    asset_inventory.append({"host": host, "fingerprints": fingerprints})

                if "server" in headers_lower:
                    server_val = headers_lower["server"].lower()
                    if any(v in server_val for v in ["apache/", "nginx/", "iis/"]):
                        findings.append({
                            "title": "Server Version Disclosure",
                            "category": "Information Disclosure",
                            "wstg_refs": ["WSTG-INFO-02"],
                            "severity": "low",
                            "confidence": 0.98,
                            "description": f"Server header reveals version: '{headers_lower['server']}'.",
                            "agent": self.name,
                        })

                for path in ["/robots.txt", "/sitemap.xml"]:
                    try:
                        r = await client.get(urljoin(base, path))
                        audit_logger.log("recon", "http", "GET", urljoin(base, path), 0, r.status_code)
                        if r.status_code == 200 and len(r.text) > 10:
                            if path == "/robots.txt":
                                for line in r.text.splitlines():
                                    if line.lower().startswith("disallow:"):
                                        p = line.split(":", 1)[1].strip()
                                        if p:
                                            routes.append({"method": "GET", "path": p, "source": "robots.txt"})
                            elif path == "/sitemap.xml":
                                locs = re.findall(r"<loc>(.*?)</loc>", r.text)
                                for loc in locs[:50]:
                                    routes.append({"method": "GET", "path": loc, "source": "sitemap"})
                    except Exception:
                        pass

                for spath in SWAGGER_PATHS:
                    try:
                        r = await client.get(urljoin(base, spath))
                        if r.status_code == 200 and ("openapi" in r.text[:200].lower() or "swagger" in r.text[:200].lower()):
                            routes.append({"method": "GET", "path": spath, "source": "openapi"})
                            try:
                                spec = r.json()
                                for p, methods in spec.get("paths", {}).items():
                                    for m in methods:
                                        if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                            routes.append({"method": m.upper(), "path": p, "source": "openapi"})
                            except Exception:
                                pass
                            break
                    except Exception:
                        pass

                for err_path in ["/thispagedoesnotexist404", "/api/v1/error_test"]:
                    try:
                        r = await client.get(urljoin(base, err_path))
                        body = r.text.lower()
                        if any(kw in body for kw in ["traceback", "stack trace", "exception", "debug", "at line"]):
                            findings.append({
                                "title": "Verbose Error Messages Expose Stack Trace",
                                "category": "Error Handling",
                                "wstg_refs": ["WSTG-ERRH-01"],
                                "severity": "low",
                                "confidence": 0.97,
                                "description": f"Error page at {err_path} reveals internal details.",
                                "agent": self.name,
                            })
                            break
                    except Exception:
                        pass

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={
                "findings": findings,
                "asset_inventory": asset_inventory,
                "routes": routes,
            },
            tool_calls=len(findings) + len(routes),
        )
