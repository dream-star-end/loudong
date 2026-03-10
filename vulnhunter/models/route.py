"""Route model — discovered API/page endpoints."""

from sqlalchemy import JSON, Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnhunter.models.base import Base, TimestampMixin, new_uuid


class Route(Base, TimestampMixin):
    __tablename__ = "routes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(50), default="crawl")
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    role_candidates: Mapped[list[str]] = mapped_column(JSON, default=list)
    params: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]
