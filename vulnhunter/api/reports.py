"""Report and findings endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnhunter.api.schemas import FindingResponse
from vulnhunter.db.session import get_db
from vulnhunter.models.finding import Finding

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{target_id}/findings", response_model=list[FindingResponse])
async def list_findings(
    target_id: str, db: AsyncSession = Depends(get_db)
) -> list[Finding]:
    result = await db.execute(
        select(Finding).where(Finding.target_id == target_id)
    )
    return list(result.scalars().all())
