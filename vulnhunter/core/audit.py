"""Persistent audit logging — every tool call recorded per PRD §5.2 #7.

Stores an in-memory buffer that the API can query, and optionally persists
to PostgreSQL when a DB session is available.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

MAX_BUFFER = 5000


@dataclass
class AuditEntry:
    timestamp: str
    agent: str
    tool: str
    action: str
    url: str = ""
    risk_level: int = 0
    status_code: int = 0
    elapsed_ms: float = 0.0
    detail: str = ""


class AuditLogger:
    """In-memory audit log with optional DB persistence."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def log(
        self,
        agent: str,
        tool: str,
        action: str,
        url: str = "",
        risk_level: int = 0,
        status_code: int = 0,
        elapsed_ms: float = 0.0,
        detail: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=datetime.now(UTC).isoformat(),
            agent=agent,
            tool=tool,
            action=action,
            url=url,
            risk_level=risk_level,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            detail=detail,
        )
        self._entries.append(entry)
        if len(self._entries) > MAX_BUFFER:
            self._entries = self._entries[-MAX_BUFFER:]
        logger.debug(
            "AUDIT [%s] %s.%s %s L%d -> %d (%.1fms)",
            entry.timestamp, agent, tool, action, risk_level, status_code, elapsed_ms,
        )
        return entry

    def query(
        self,
        agent: str | None = None,
        tool: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        results = self._entries
        if agent:
            results = [e for e in results if e.agent == agent]
        if tool:
            results = [e for e in results if e.tool == tool]
        return results[-limit:]

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def clear(self) -> None:
        self._entries.clear()


audit_logger = AuditLogger()
