"""Input Agent (WSTG-INPV) — input validation, parameter profiling, injection detection."""

from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent


class InputAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("input")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "enumerate_input_points"},
            {"action": "profile_parameters"},
            {"action": "anomaly_probe"},
            {"action": "cluster_responses"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        plan = await self.plan(context)
        self.logger.info("Input agent plan: %d actions", len(plan))
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={"plan": plan, "param_profiles": [], "high_risk_inputs": []},
            tool_calls=len(plan),
        )
