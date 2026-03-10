"""Base agent with ReAct loop skeleton and integrated LLM + SecureHttpClient."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from vulnhunter.llm.client import LLMClient
from vulnhunter.tools.http_client import SecureHttpClient


class AgentStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentResult:
    agent_name: str
    status: AgentStatus
    outputs: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    tool_calls: int = 0


class BaseAgent(ABC):
    """Abstract base for all VulnHunter agents.

    Each agent follows a ReAct (Reason-Act) loop:
    1. Observe current state
    2. Reason about next action (optionally via LLM)
    3. Act via deterministic tools (SecureHttpClient)
    4. Evaluate result
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.status = AgentStatus.IDLE
        self.logger = logging.getLogger(f"vulnhunter.agent.{name}")
        self.llm = LLMClient()

    def create_http_client(
        self, allowed_hosts: list[str], max_risk_level: int = 1
    ) -> SecureHttpClient:
        """Create a SecureHttpClient bound to this agent with full PRD §5.2 controls."""
        return SecureHttpClient(
            allowed_hosts=allowed_hosts,
            agent_name=self.name,
            max_risk_level=max_risk_level,
        )

    @abstractmethod
    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate a list of planned actions from the given context."""

    @abstractmethod
    async def execute(self, context: dict[str, Any]) -> AgentResult:
        """Run the agent's task and return results."""

    async def run(self, context: dict[str, Any]) -> AgentResult:
        self.status = AgentStatus.RUNNING
        self.logger.info("Agent %s started", self.name)
        try:
            result = await self.execute(context)
            self.status = AgentStatus.COMPLETED
            self.logger.info("Agent %s completed", self.name)
            return result
        except Exception as e:
            self.status = AgentStatus.FAILED
            self.logger.error("Agent %s failed: %s", self.name, e)
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILED,
                errors=[str(e)],
            )
