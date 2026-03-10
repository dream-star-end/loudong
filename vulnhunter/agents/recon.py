"""Recon Agent (WSTG-INFO) — asset discovery, fingerprinting, route map."""

from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent


class ReconAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("recon")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        hosts = context.get("allowed_hosts", [])
        return [
            {"action": "fetch_robots_sitemap", "hosts": hosts},
            {"action": "fingerprint_tech_stack", "hosts": hosts},
            {"action": "discover_api_specs", "hosts": hosts},
            {"action": "enumerate_entry_points", "hosts": hosts},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        self.logger.info("Recon plan: %d actions", len(plan))
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"plan": plan, "asset_inventory": [], "route_map": []},
            tool_calls=len(plan),
        )
