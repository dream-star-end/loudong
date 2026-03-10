"""Tests for agent orchestration and sub-agent execution."""

import pytest

from vulnhunter.agents.authz import AuthZAgent
from vulnhunter.agents.base import AgentStatus
from vulnhunter.agents.bizlogic import BizLogicAgent
from vulnhunter.agents.crawl import CrawlAgent
from vulnhunter.agents.evidence_agent import EvidenceAgent
from vulnhunter.agents.input_agent import InputAgent
from vulnhunter.agents.orchestrator import OrchestratorAgent
from vulnhunter.agents.recon import ReconAgent

SAMPLE_CONTEXT = {
    "target_id": "test-target-1",
    "allowed_hosts": ["app.example.com"],
    "roles": ["guest", "user", "admin"],
    "depth": "standard",
}


@pytest.mark.asyncio
async def test_orchestrator_plans_tasks() -> None:
    orch = OrchestratorAgent()
    plan = await orch.plan(SAMPLE_CONTEXT)
    assert len(plan) == 5
    agent_names = [t["agent"] for t in plan]
    assert "recon" in agent_names
    assert "authz" in agent_names


@pytest.mark.asyncio
async def test_orchestrator_full_run() -> None:
    orch = OrchestratorAgent()
    orch.register_agent(ReconAgent())
    orch.register_agent(CrawlAgent())
    orch.register_agent(AuthZAgent())
    orch.register_agent(InputAgent())
    orch.register_agent(BizLogicAgent())
    orch.register_agent(EvidenceAgent())

    result = await orch.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert len(result.outputs["sub_results"]) == 6


@pytest.mark.asyncio
async def test_recon_agent() -> None:
    agent = ReconAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "asset_inventory" in result.outputs


@pytest.mark.asyncio
async def test_crawl_agent() -> None:
    agent = CrawlAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "page_graph" in result.outputs


@pytest.mark.asyncio
async def test_authz_agent() -> None:
    agent = AuthZAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "role_matrix" in result.outputs


@pytest.mark.asyncio
async def test_input_agent() -> None:
    agent = InputAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "param_profiles" in result.outputs


@pytest.mark.asyncio
async def test_bizlogic_agent() -> None:
    agent = BizLogicAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "bypass_findings" in result.outputs


@pytest.mark.asyncio
async def test_evidence_agent() -> None:
    agent = EvidenceAgent()
    result = await agent.run(SAMPLE_CONTEXT)
    assert result.status == AgentStatus.COMPLETED
    assert "confirmed_findings" in result.outputs
