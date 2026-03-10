"""Three-layer memory system per PRD §6.1.

Layer 1 — Short-term (Redis): current scan state, recent actions, session cache.
Layer 2 — Task-level (PostgreSQL): route inventory, request samples, confirmed items.
Layer 3 — Long-term knowledge (PG/JSON): WSTG templates, framework signatures, FP rules.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ShortTermMemory:
    """Redis-backed scan state cache. Falls back to in-memory dict."""

    def __init__(self) -> None:
        self._local: dict[str, Any] = {}
        self._redis = None

    async def connect(self, redis_url: str) -> None:
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(redis_url)
            await self._redis.ping()
            logger.info("ShortTermMemory connected to Redis")
        except Exception as e:
            logger.warning("Redis not available for memory, using local: %s", e)
            self._redis = None

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        serialized = json.dumps(value, default=str)
        if self._redis:
            await self._redis.set(f"vh:{key}", serialized, ex=ttl)
        self._local[key] = value

    async def get(self, key: str) -> Any:
        if self._redis:
            raw = await self._redis.get(f"vh:{key}")
            if raw:
                return json.loads(raw)
        return self._local.get(key)

    async def delete(self, key: str) -> None:
        if self._redis:
            await self._redis.delete(f"vh:{key}")
        self._local.pop(key, None)

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()


class TaskMemory:
    """In-process task-level memory (backed by the same PG used for models).

    Stores intermediate scan results accessible across agents within a single task.
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def store(self, key: str, value: Any) -> None:
        self._store[key] = value

    def retrieve(self, key: str) -> Any:
        return self._store.get(key)

    def all(self) -> dict[str, Any]:
        return dict(self._store)

    def clear(self) -> None:
        self._store.clear()


class KnowledgeBase:
    """Long-term knowledge: WSTG templates, framework signatures, FP rules.

    Loaded from JSON files on disk. Extensible to PG + vector search in future.
    """

    def __init__(self) -> None:
        self.wstg_templates: dict[str, Any] = {}
        self.framework_signatures: dict[str, list[str]] = {}
        self.fp_rules: list[dict[str, Any]] = []
        self._load_defaults()

    def _load_defaults(self) -> None:
        self.wstg_templates = {
            "WSTG-CONF-07": {"title": "Test HTTP Security Headers", "checks": ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options"]},
            "WSTG-SESS-02": {"title": "Test Cookie Attributes", "checks": ["Secure", "HttpOnly", "SameSite"]},
            "WSTG-SESS-06": {"title": "Test Session Timeout", "checks": ["exp claim", "max-age"]},
            "WSTG-ATHN-07": {"title": "Test Password Policy", "checks": ["min length", "complexity", "common passwords"]},
            "WSTG-ATHN-09": {"title": "Test JWT Security", "checks": ["algorithm", "expiration", "signature"]},
            "WSTG-ATHZ-04": {"title": "Test IDOR", "checks": ["object ID prediction", "role-based access"]},
            "WSTG-INPV-01": {"title": "Test Reflected XSS", "checks": ["input reflection", "encoding"]},
            "WSTG-INPV-05": {"title": "Test SQL Injection", "checks": ["error-based", "boolean-based"]},
            "WSTG-ERRH-01": {"title": "Test Error Handling", "checks": ["stack traces", "debug info"]},
            "WSTG-BUSL-01": {"title": "Test Business Logic", "checks": ["step bypass", "flow integrity"]},
            "WSTG-BUSL-05": {"title": "Test Rate Limiting", "checks": ["brute force", "enumeration"]},
            "WSTG-INFO-02": {"title": "Test Server Fingerprinting", "checks": ["Server header", "version disclosure"]},
        }

        self.framework_signatures = {
            "django": ["csrfmiddlewaretoken", "django", "wsgiref"],
            "rails": ["X-Request-Id", "_rails_session", "action_dispatch"],
            "spring": ["JSESSIONID", "X-Application-Context"],
            "express": ["X-Powered-By: Express", "connect.sid"],
            "laravel": ["laravel_session", "XSRF-TOKEN"],
            "flask": ["Werkzeug", "flask"],
            "fastapi": ["fastapi", "uvicorn", "starlette"],
            "asp.net": ["X-AspNet-Version", "X-AspNetMvc-Version", ".ASPXAUTH"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
        }

        self.fp_rules = [
            {"pattern": "404 page with custom content", "action": "ignore_if_custom_error"},
            {"pattern": "redirect to login", "action": "not_authz_bypass"},
        ]

    def match_framework(self, headers: dict[str, str], body: str = "") -> list[str]:
        matches = []
        combined = " ".join(headers.values()) + " " + body[:2000]
        combined_lower = combined.lower()
        for framework, signatures in self.framework_signatures.items():
            for sig in signatures:
                if sig.lower() in combined_lower:
                    matches.append(framework)
                    break
        return matches


short_term = ShortTermMemory()
task_memory = TaskMemory()
knowledge_base = KnowledgeBase()
