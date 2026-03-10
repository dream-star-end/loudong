"""Admin endpoints — audit logs, HITL approvals, system status."""

from dataclasses import asdict

from fastapi import APIRouter

from vulnhunter.core.audit import audit_logger
from vulnhunter.core.hitl import approval_queue

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit")
async def list_audit_logs(agent: str | None = None, limit: int = 100) -> list[dict]:
    entries = audit_logger.query(agent=agent, limit=limit)
    return [asdict(e) for e in entries]


@router.get("/approvals")
async def list_pending_approvals() -> list[dict]:
    return [asdict(r) for r in approval_queue.list_pending()]


@router.get("/approvals/all")
async def list_all_approvals() -> list[dict]:
    return [asdict(r) for r in approval_queue.list_all()]


@router.post("/approvals/{request_id}/approve")
async def approve_action(request_id: str) -> dict:
    ok = approval_queue.approve(request_id)
    return {"success": ok}


@router.post("/approvals/{request_id}/reject")
async def reject_action(request_id: str) -> dict:
    ok = approval_queue.reject(request_id)
    return {"success": ok}
