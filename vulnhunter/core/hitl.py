"""HITL (Human-In-The-Loop) approval mechanism per PRD §5.2 #6.

L2/L3 actions are queued for human approval before execution.
Provides an API-compatible approval queue.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

logger = logging.getLogger(__name__)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    id: str
    agent: str
    action: str
    url: str
    risk_level: int
    detail: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: str = ""
    resolved_at: str = ""
    resolver: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(UTC).isoformat()


class ApprovalQueue:
    """In-memory approval queue for HITL review."""

    def __init__(self) -> None:
        self._queue: dict[str, ApprovalRequest] = {}

    def submit(
        self,
        agent: str,
        action: str,
        url: str,
        risk_level: int,
        detail: str = "",
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            id=str(uuid.uuid4()),
            agent=agent,
            action=action,
            url=url,
            risk_level=risk_level,
            detail=detail,
        )
        self._queue[req.id] = req
        logger.info("HITL approval requested: [%s] %s %s (L%d)", req.id[:8], agent, action, risk_level)
        return req

    def approve(self, request_id: str, resolver: str = "human") -> bool:
        req = self._queue.get(request_id)
        if not req or req.status != ApprovalStatus.PENDING:
            return False
        req.status = ApprovalStatus.APPROVED
        req.resolved_at = datetime.now(UTC).isoformat()
        req.resolver = resolver
        logger.info("HITL approved: [%s]", request_id[:8])
        return True

    def reject(self, request_id: str, resolver: str = "human") -> bool:
        req = self._queue.get(request_id)
        if not req or req.status != ApprovalStatus.PENDING:
            return False
        req.status = ApprovalStatus.REJECTED
        req.resolved_at = datetime.now(UTC).isoformat()
        req.resolver = resolver
        logger.info("HITL rejected: [%s]", request_id[:8])
        return True

    def list_pending(self) -> list[ApprovalRequest]:
        return [r for r in self._queue.values() if r.status == ApprovalStatus.PENDING]

    def list_all(self, limit: int = 50) -> list[ApprovalRequest]:
        return list(self._queue.values())[-limit:]

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._queue.get(request_id)


approval_queue = ApprovalQueue()
