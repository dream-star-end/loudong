"""Target management endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnhunter.api.schemas import TargetCreate, TargetResponse
from vulnhunter.db.session import get_db
from vulnhunter.models.target import Target

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(
    body: TargetCreate, db: AsyncSession = Depends(get_db)
) -> Target:
    target = Target(
        name=body.name,
        allowed_hosts=body.allowed_hosts,
        auth_mode=body.auth_mode,
        roles=body.roles,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/", response_model=list[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)) -> list[Target]:
    result = await db.execute(select(Target))
    return list(result.scalars().all())


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)) -> Target:
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target
