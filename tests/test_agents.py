"""Tests for the new real agent implementations."""

import pytest

from vulnhunter.agents.base import AgentStatus
from vulnhunter.agents.evidence_agent import EvidenceAgent

SAMPLE_FINDINGS = [
    {
        "title": "Missing HSTS Header",
        "category": "Security Misconfiguration",
        "wstg_refs": ["WSTG-CONF-07"],
        "severity": "medium",
        "confidence": 0.95,
        "description": "No HSTS header.",
        "agent": "recon",
    },
    {
        "title": "Missing HSTS Header",
        "category": "Security Misconfiguration",
        "wstg_refs": ["WSTG-CONF-07"],
        "severity": "medium",
        "confidence": 0.90,
        "description": "Duplicate finding.",
        "agent": "recon",
    },
    {
        "title": "Cookie Without Secure Flag",
        "category": "Session Management",
        "wstg_refs": ["WSTG-SESS-02"],
        "severity": "medium",
        "confidence": 0.95,
        "description": "Session cookie lacks Secure flag.",
        "agent": "authz",
    },
]


@pytest.mark.asyncio
async def test_evidence_dedup_and_scoring() -> None:
    agent = EvidenceAgent()
    result = await agent.run({"all_findings": SAMPLE_FINDINGS})
    assert result.status == AgentStatus.COMPLETED
    stats = result.outputs["stats"]
    assert stats["total_raw"] == 3
    assert stats["after_dedup"] == 2
    assert len(result.outputs["findings"]) == 2


@pytest.mark.asyncio
async def test_evidence_standard_mapping() -> None:
    agent = EvidenceAgent()
    result = await agent.run({"all_findings": SAMPLE_FINDINGS})
    for f in result.outputs["findings"]:
        assert "asvs_refs" in f
        assert "top10_refs" in f
