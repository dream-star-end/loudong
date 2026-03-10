"""Crawl Agent — page/state discovery, workflow graph building."""

from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent


class CrawlAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("crawl")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "login_as_role", "roles": context.get("roles", [])},
            {"action": "traverse_pages"},
            {"action": "record_workflows"},
            {"action": "build_page_graph"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        self.logger.info("Crawl plan: %d actions", len(plan))
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"plan": plan, "page_graph": {}, "workflows": []},
            tool_calls=len(plan),
        )
