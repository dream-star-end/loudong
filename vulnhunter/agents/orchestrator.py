"""Orchestrator Agent — the real scan pipeline per PRD §3.1.

Phases: P0(manifest) → P1(recon) → P2(crawl) → P3(baseline=authz) →
        P4(input+bizlogic) → P5(evidence) → P6(report)

The Orchestrator only plans and dispatches. It never executes tests directly.
"""

import logging
from typing import Any

from vulnhunter.agents.authz import AuthZAgent
from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent
from vulnhunter.agents.bizlogic import BizLogicAgent
from vulnhunter.agents.crawl import CrawlAgent
from vulnhunter.agents.evidence_agent import EvidenceAgent
from vulnhunter.agents.input_agent import InputAgent
from vulnhunter.agents.recon import ReconAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("orchestrator")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        target_hosts = context.get("allowed_hosts", [])
        return [
            {"phase": "P1", "agent": "recon", "target_hosts": target_hosts},
            {"phase": "P2", "agent": "crawl", "target_hosts": target_hosts},
            {"phase": "P3", "agent": "authz", "target_hosts": target_hosts},
            {"phase": "P4a", "agent": "input", "target_hosts": target_hosts},
            {"phase": "P4b", "agent": "bizlogic", "target_hosts": target_hosts},
            {"phase": "P5", "agent": "evidence"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        all_findings: list[dict[str, Any]] = []
        sub_results: list[dict[str, Any]] = []
        agent_stats: list[dict[str, Any]] = []

        recon = ReconAgent()
        self.logger.info("P1: Recon starting")
        recon_result = await recon.run(context)
        recon_findings = recon_result.outputs.get("findings", [])
        all_findings.extend(recon_findings)
        routes = recon_result.outputs.get("routes", [])
        sub_results.append({"agent": "recon", "status": recon_result.status.value})
        agent_stats.append({"name": "recon", "status": recon_result.status.value,
                           "tool_calls": recon_result.tool_calls, "findings_count": len(recon_findings)})

        crawl_context = {**context, "routes": routes}
        crawl = CrawlAgent()
        self.logger.info("P2: Crawl starting")
        crawl_result = await crawl.run(crawl_context)
        routes = crawl_result.outputs.get("routes", routes)
        forms = crawl_result.outputs.get("forms", [])
        sub_results.append({"agent": "crawl", "status": crawl_result.status.value})
        agent_stats.append({"name": "crawl", "status": crawl_result.status.value,
                           "tool_calls": crawl_result.outputs.get("pages_visited", 0), "findings_count": 0})

        authz = AuthZAgent()
        self.logger.info("P3: AuthZ starting")
        authz_result = await authz.run(context)
        authz_findings = authz_result.outputs.get("findings", [])
        all_findings.extend(authz_findings)
        sub_results.append({"agent": "authz", "status": authz_result.status.value})
        agent_stats.append({"name": "authz", "status": authz_result.status.value,
                           "tool_calls": authz_result.tool_calls, "findings_count": len(authz_findings)})

        input_context = {**context, "routes": routes, "forms": forms}
        input_agent = InputAgent()
        self.logger.info("P4a: Input starting")
        input_result = await input_agent.run(input_context)
        input_findings = input_result.outputs.get("findings", [])
        all_findings.extend(input_findings)
        sub_results.append({"agent": "input", "status": input_result.status.value})
        agent_stats.append({"name": "input", "status": input_result.status.value,
                           "tool_calls": input_result.tool_calls, "findings_count": len(input_findings)})

        biz_context = {**context, "routes": routes}
        bizlogic = BizLogicAgent()
        self.logger.info("P4b: BizLogic starting")
        biz_result = await bizlogic.run(biz_context)
        biz_findings = biz_result.outputs.get("findings", [])
        all_findings.extend(biz_findings)
        sub_results.append({"agent": "bizlogic", "status": biz_result.status.value})
        agent_stats.append({"name": "bizlogic", "status": biz_result.status.value,
                           "tool_calls": biz_result.tool_calls, "findings_count": len(biz_findings)})

        evidence = EvidenceAgent()
        self.logger.info("P5: Evidence starting")
        ev_context = {**context, "all_findings": all_findings}
        ev_result = await evidence.run(ev_context)
        final_findings = ev_result.outputs.get("findings", [])
        ev_stats = ev_result.outputs.get("stats", {})
        sub_results.append({"agent": "evidence", "status": ev_result.status.value})
        agent_stats.append({"name": "evidence", "status": ev_result.status.value,
                           "tool_calls": 0, "findings_count": len(final_findings)})

        self.logger.info(
            "Scan complete: %d raw → %d deduped → %d confirmed + %d review",
            ev_stats.get("total_raw", 0),
            ev_stats.get("after_dedup", 0),
            ev_stats.get("confirmed", 0),
            ev_stats.get("needs_review", 0),
        )

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={
                "plan": plan,
                "sub_results": sub_results,
                "findings": final_findings,
                "evidence_stats": ev_stats,
                "agent_stats": agent_stats,
                "routes_discovered": len(routes),
                "forms_discovered": len(forms),
            },
            tool_calls=sum(a.get("tool_calls", 0) for a in agent_stats),
        )
