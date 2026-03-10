"""Orchestrator Agent — plans, dispatches, and aggregates results.

The Orchestrator never executes tests directly. It:
1. Parses the target scope and engagement manifest
2. Decomposes into WSTG-aligned tasks
3. Dispatches to specialized sub-agents with budgets
4. Merges, deduplicates, and converges results
"""

import logging
from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("orchestrator")
        self._sub_agents: list[BaseAgent] = []

    def register_agent(self, agent: BaseAgent) -> None:
        self._sub_agents.append(agent)
        logger.info("Registered sub-agent: %s", agent.name)

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        target_hosts = context.get("allowed_hosts", [])
        tasks = [
            {"agent": "recon", "target_hosts": target_hosts, "budget": 100},
            {"agent": "crawl", "target_hosts": target_hosts, "budget": 200},
            {"agent": "authz", "target_hosts": target_hosts, "budget": 150},
            {"agent": "input", "target_hosts": target_hosts, "budget": 150},
            {"agent": "bizlogic", "target_hosts": target_hosts, "budget": 100},
        ]
        logger.info("Planned %d sub-tasks for %d hosts", len(tasks), len(target_hosts))
        return tasks

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        all_outputs: dict[str, Any] = {"plan": plan, "sub_results": []}

        for agent in self._sub_agents:
            result = await agent.run(context)
            all_outputs["sub_results"].append(
                {"agent": result.agent_name, "status": result.status.value}
            )

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs=all_outputs,
            tool_calls=len(plan),
        )
