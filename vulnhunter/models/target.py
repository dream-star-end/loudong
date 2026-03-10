"""Target model — the web application under test."""

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnhunter.models.base import Base, TimestampMixin, new_uuid


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255))
    allowed_hosts: Mapped[list[str]] = mapped_column(JSON, default=list)
    auth_mode: Mapped[str] = mapped_column(String(50), default="cookie")
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="created")
