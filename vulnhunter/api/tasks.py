"""Task execution endpoints — real agent pipeline, report generation."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnhunter.agents.orchestrator import OrchestratorAgent
from vulnhunter.api.schemas import TaskCreate, TaskResponse
from vulnhunter.core.manifest import EngagementManifest
from vulnhunter.core.report import generate_agent_report, generate_dev_report
from vulnhunter.db.session import get_db
from vulnhunter.models.finding import Finding
from vulnhunter.models.target import Target

router = APIRouter(prefix="/tasks", tags=["tasks"])

_last_report_cache: dict[str, str] = {}


@router.post("/", response_model=TaskResponse, status_code=201)
async def create_task(
    body: TaskCreate, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    result = await db.execute(select(Target).where(Target.id == body.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    manifest = EngagementManifest.from_target(
        name=target.name,
        hosts=target.allowed_hosts,
        roles=target.roles,
        depth=body.depth,
    )

    context = {
        "target_id": target.id,
        "allowed_hosts": manifest.hosts,
        "roles": [r.name for r in manifest.roles],
        "depth": manifest.testing_profile.depth,
        "manifest": manifest,
    }

    orchestrator = OrchestratorAgent()
    agent_result = await orchestrator.run(context)

    final_findings = agent_result.outputs.get("findings", [])
    for f in final_findings:
        finding = Finding(
            target_id=target.id,
            title=f.get("title", ""),
            category=f.get("category", ""),
            wstg_refs=f.get("wstg_refs", []),
            asvs_refs=f.get("asvs_refs", []),
            severity=f.get("severity", "info"),
            confidence=f.get("confidence", 0.0),
            description=f.get("description", ""),
            status=f.get("status", "needs_review"),
        )
        db.add(finding)

    target.status = "scanned"
    await db.commit()

    dev_report_html = generate_dev_report(
        target_name=target.name,
        hosts=target.allowed_hosts,
        findings=final_findings,
    )
    agent_report_html = generate_agent_report(
        target_name=target.name,
        agent_stats=agent_result.outputs.get("agent_stats", []),
        evidence_stats=agent_result.outputs.get("evidence_stats"),
    )
    _last_report_cache[f"{target.id}_dev"] = dev_report_html
    _last_report_cache[f"{target.id}_agent"] = agent_report_html

    return {
        "task_id": str(uuid.uuid4()),
        "target_id": target.id,
        "status": agent_result.status.value,
        "plan": agent_result.outputs.get("plan", []),
        "sub_results": agent_result.outputs.get("sub_results", []),
        "findings_count": len(final_findings),
    }


@router.get("/report/{target_id}/dev", response_class=HTMLResponse)
async def get_dev_report(target_id: str) -> HTMLResponse:
    html = _last_report_cache.get(f"{target_id}_dev")
    if not html:
        raise HTTPException(status_code=404, detail="Report not found. Run a scan first.")
    return HTMLResponse(content=html)


@router.get("/report/{target_id}/agent", response_class=HTMLResponse)
async def get_agent_report(target_id: str) -> HTMLResponse:
    html = _last_report_cache.get(f"{target_id}_agent")
    if not html:
        raise HTTPException(status_code=404, detail="Report not found. Run a scan first.")
    return HTMLResponse(content=html)
