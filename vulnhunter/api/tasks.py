"""Task execution endpoints — trigger and monitor agent runs."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnhunter.agents.authz import AuthZAgent
from vulnhunter.agents.bizlogic import BizLogicAgent
from vulnhunter.agents.crawl import CrawlAgent
from vulnhunter.agents.evidence_agent import EvidenceAgent
from vulnhunter.agents.input_agent import InputAgent
from vulnhunter.agents.orchestrator import OrchestratorAgent
from vulnhunter.agents.recon import ReconAgent
from vulnhunter.agents.scan_simulator import generate_findings
from vulnhunter.api.schemas import TaskCreate, TaskResponse
from vulnhunter.db.session import get_db
from vulnhunter.models.finding import Finding
from vulnhunter.models.target import Target

router = APIRouter(prefix="/tasks", tags=["tasks"])


def _build_orchestrator() -> OrchestratorAgent:
    orch = OrchestratorAgent()
    orch.register_agent(ReconAgent())
    orch.register_agent(CrawlAgent())
    orch.register_agent(AuthZAgent())
    orch.register_agent(InputAgent())
    orch.register_agent(BizLogicAgent())
    orch.register_agent(EvidenceAgent())
    return orch


@router.post("/", response_model=TaskResponse, status_code=201)
async def create_task(
    body: TaskCreate, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    result = await db.execute(select(Target).where(Target.id == body.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    context = {
        "target_id": target.id,
        "allowed_hosts": target.allowed_hosts,
        "roles": target.roles,
        "depth": body.depth,
    }

    orchestrator = _build_orchestrator()
    agent_result = await orchestrator.run(context)

    sim_findings = generate_findings(body.depth)
    for sf in sim_findings:
        finding = Finding(
            target_id=target.id,
            title=sf.title,
            category=sf.category,
            wstg_refs=sf.wstg_refs,
            asvs_refs=sf.asvs_refs,
            severity=sf.severity,
            confidence=sf.confidence,
            description=sf.description,
            status="confirmed" if sf.confidence >= 0.9 else "needs_review",
        )
        db.add(finding)

    target.status = "scanned"
    await db.commit()

    return {
        "task_id": str(uuid.uuid4()),
        "target_id": target.id,
        "status": agent_result.status.value,
        "plan": agent_result.outputs.get("plan", []),
        "sub_results": agent_result.outputs.get("sub_results", []),
        "findings_count": len(sim_findings),
    }
