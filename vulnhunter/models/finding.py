"""Finding model — a confirmed or suspected vulnerability."""

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from vulnhunter.models.base import Base, TimestampMixin, new_uuid


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    title: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(100))
    wstg_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    asvs_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="needs_review")
    description: Mapped[str] = mapped_column(Text, default="")
