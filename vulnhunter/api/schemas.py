"""Pydantic request/response schemas for the API."""

from pydantic import BaseModel


class TargetCreate(BaseModel):
    name: str
    allowed_hosts: list[str]
    auth_mode: str = "cookie"
    roles: list[str] = []


class TargetResponse(BaseModel):
    id: str
    name: str
    allowed_hosts: list[str]
    auth_mode: str
    roles: list[str]
    status: str

    model_config = {"from_attributes": True}


class TaskCreate(BaseModel):
    target_id: str
    depth: str = "standard"


class TaskResponse(BaseModel):
    task_id: str
    target_id: str
    status: str
    plan: list[dict[str, object]]


class FindingResponse(BaseModel):
    id: str
    target_id: str
    title: str
    category: str
    severity: str
    confidence: float
    status: str
    wstg_refs: list[str]
    description: str

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    status: str
    version: str
    services: dict[str, str]
