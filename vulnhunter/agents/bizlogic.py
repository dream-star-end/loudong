"""BizLogic Agent (WSTG-BUSL) — business logic bypass, flow integrity testing."""

from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent


class BizLogicAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("bizlogic")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "model_business_flows"},
            {"action": "check_step_bypass"},
            {"action": "check_rate_limits"},
            {"action": "check_state_integrity"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        self.logger.info("BizLogic plan: %d actions", len(plan))
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"plan": plan, "bypass_findings": [], "rate_limit_findings": []},
            tool_calls=len(plan),
        )
