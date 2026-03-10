"""Tests for the FastAPI endpoints (using httpx test client)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_create_and_list_targets(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/targets/",
        json={
            "name": "Test App",
            "allowed_hosts": ["app.test.com"],
            "roles": ["guest", "admin"],
        },
    )
    assert resp.status_code == 201
    target = resp.json()
    assert target["name"] == "Test App"
    assert target["status"] == "created"

    resp2 = await client.get("/api/v1/targets/")
    assert resp2.status_code == 200


@pytest.mark.asyncio
async def test_get_target_not_found(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/targets/nonexistent")
    assert resp.status_code == 404
