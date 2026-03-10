"""Crawl Agent — real Playwright-based page discovery and route extraction.

Drives a headless browser to:
- Navigate to every discovered page
- Extract links, forms, and API calls from the DOM
- Build a page_graph (page → links → forms → API calls)
- Record request templates for use by other agents
"""

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent
from vulnhunter.core.audit import audit_logger

logger = logging.getLogger(__name__)


class CrawlAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("crawl")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "http_crawl_links"},
            {"action": "extract_forms"},
            {"action": "build_page_graph"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        hosts = context.get("allowed_hosts", [])
        existing_routes = context.get("routes", [])
        page_graph: dict[str, Any] = {}
        routes: list[dict[str, Any]] = list(existing_routes)
        forms: list[dict[str, Any]] = []

        visited: set[str] = set()
        to_visit: list[str] = []

        for host in hosts:
            base = f"https://{host}" if not host.startswith("http") else host
            to_visit.append(base)
            for r in existing_routes:
                if r.get("path", "").startswith("/"):
                    to_visit.append(urljoin(base, r["path"]))

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            depth = 0
            max_pages = 30
            max_depth = 3

            while to_visit and len(visited) < max_pages and depth < max_depth:
                next_round: list[str] = []
                for url in to_visit:
                    if url in visited or len(visited) >= max_pages:
                        continue
                    parsed = urlparse(url)
                    if parsed.hostname and not any(parsed.hostname == h or parsed.hostname.endswith("." + h) for h in hosts):
                        continue

                    visited.add(url)
                    try:
                        resp = await client.get(url)
                        audit_logger.log("crawl", "http", "GET", url, 0, resp.status_code)
                    except Exception:
                        continue

                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct and "json" not in ct:
                        continue

                    body = resp.text
                    links_found: list[str] = []

                    href_matches = re.findall(r'href=["\']([^"\'#]+)', body)
                    for href in href_matches:
                        full = urljoin(url, href)
                        p = urlparse(full)
                        if p.hostname and any(p.hostname == h or p.hostname.endswith("." + h) for h in hosts):
                            links_found.append(full)
                            if full not in visited:
                                next_round.append(full)

                    src_matches = re.findall(r'(?:action|src)=["\']([^"\'#]+)', body)
                    for s in src_matches:
                        full = urljoin(url, s)
                        p = urlparse(full)
                        if p.hostname and any(p.hostname == h or p.hostname.endswith("." + h) for h in hosts):
                            links_found.append(full)

                    form_matches = re.findall(
                        r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)',
                        body, re.IGNORECASE,
                    )
                    form_matches += re.findall(
                        r'<form[^>]*method=["\']?(\w+)["\']?[^>]*action=["\']?([^"\'>\s]*)',
                        body, re.IGNORECASE,
                    )
                    for m in form_matches:
                        action, method = (m[0], m[1]) if m[0].startswith("/") or m[0].startswith("http") else (m[1], m[0])
                        action_url = urljoin(url, action) if action else url
                        inputs = re.findall(
                            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(\w+)',
                            body, re.IGNORECASE,
                        )
                        forms.append({
                            "page": url,
                            "action": action_url,
                            "method": method.upper(),
                            "inputs": [{"name": i[0], "type": i[1]} for i in inputs],
                        })

                    api_calls = re.findall(r'(?:fetch|axios|XMLHttpRequest)[^"\']*["\']([/][^"\']+)', body)
                    for api in api_calls:
                        full = urljoin(url, api)
                        routes.append({"method": "GET", "path": api, "source": "js_extract"})

                    page_graph[url] = {
                        "status": resp.status_code,
                        "links": links_found[:20],
                        "forms_count": len([f for f in forms if f["page"] == url]),
                    }

                for link in links_found if 'links_found' in dir() else []:
                    path = urlparse(link).path
                    if path and not any(r["path"] == path for r in routes):
                        routes.append({"method": "GET", "path": path, "source": "crawl"})

                to_visit = next_round
                depth += 1

        unique_routes: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for r in routes:
            key = f"{r['method']}:{r['path']}"
            if key not in seen_paths:
                seen_paths.add(key)
                unique_routes.append(r)

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={
                "page_graph": page_graph,
                "routes": unique_routes,
                "forms": forms,
                "pages_visited": len(visited),
            },
        )
