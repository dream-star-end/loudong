"""Report, findings, and dashboard stats endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnhunter.api.schemas import FindingResponse, StatsResponse
from vulnhunter.db.session import get_db
from vulnhunter.models.finding import Finding
from vulnhunter.models.target import Target

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{target_id}/findings", response_model=list[FindingResponse])
async def list_findings(
    target_id: str, db: AsyncSession = Depends(get_db)
) -> list[Finding]:
    result = await db.execute(
        select(Finding).where(Finding.target_id == target_id)
    )
    return list(result.scalars().all())


@router.get("/stats/dashboard", response_model=StatsResponse)
async def dashboard_stats(db: AsyncSession = Depends(get_db)) -> dict:
    target_count_result = await db.execute(select(func.count(Target.id)))
    total_targets = target_count_result.scalar() or 0

    scan_count_result = await db.execute(
        select(func.count(Target.id)).where(Target.status == "scanned")
    )
    total_scans = scan_count_result.scalar() or 0

    finding_count_result = await db.execute(select(func.count(Finding.id)))
    total_findings = finding_count_result.scalar() or 0

    sev_rows = await db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in sev_rows.all()}

    cat_rows = await db.execute(
        select(Finding.category, func.count(Finding.id)).group_by(Finding.category)
    )
    category_breakdown = {row[0]: row[1] for row in cat_rows.all()}

    recent_result = await db.execute(
        select(Finding).order_by(Finding.created_at.desc()).limit(10)
    )
    recent_findings = list(recent_result.scalars().all())

    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "category_breakdown": category_breakdown,
        "recent_findings": recent_findings,
    }
