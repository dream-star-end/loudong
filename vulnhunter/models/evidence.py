"""Evidence model — proof artifact for a finding."""

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from vulnhunter.models.base import Base, TimestampMixin, new_uuid


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    type: Mapped[str] = mapped_column(String(30))
    request_ref: Mapped[str] = mapped_column(Text, default="")
    response_ref: Mapped[str] = mapped_column(Text, default="")
    screenshot_ref: Mapped[str] = mapped_column(String(500), default="")
    note: Mapped[str] = mapped_column(Text, default="")
