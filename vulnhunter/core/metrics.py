"""Evaluation metrics per PRD §11.

Coverage: page, route, role, business flow coverage.
Quality: false positive rate, false negative rate, reproducibility, actionability.
Agent: token consumption, tool calls, evidence per finding, human approval ratio.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanMetrics:
    pages_visited: int = 0
    routes_discovered: int = 0
    forms_discovered: int = 0
    roles_tested: int = 0

    total_findings_raw: int = 0
    total_findings_deduped: int = 0
    total_confirmed: int = 0
    total_needs_review: int = 0

    severity_critical: int = 0
    severity_high: int = 0
    severity_medium: int = 0
    severity_low: int = 0
    severity_info: int = 0

    total_tool_calls: int = 0
    total_llm_tokens: int = 0
    human_approvals: int = 0

    agent_stats: list[dict[str, Any]] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        total = self.total_confirmed + self.total_needs_review
        return self.total_needs_review / total if total > 0 else 0.0

    @property
    def confirmation_rate(self) -> float:
        total = self.total_confirmed + self.total_needs_review
        return self.total_confirmed / total if total > 0 else 0.0

    @property
    def avg_evidence_per_finding(self) -> float:
        return self.total_tool_calls / max(self.total_confirmed, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": {
                "pages_visited": self.pages_visited,
                "routes_discovered": self.routes_discovered,
                "forms_discovered": self.forms_discovered,
                "roles_tested": self.roles_tested,
            },
            "quality": {
                "total_raw": self.total_findings_raw,
                "total_deduped": self.total_findings_deduped,
                "confirmed": self.total_confirmed,
                "needs_review": self.total_needs_review,
                "confirmation_rate": round(self.confirmation_rate, 2),
                "false_positive_rate": round(self.false_positive_rate, 2),
            },
            "severity": {
                "critical": self.severity_critical,
                "high": self.severity_high,
                "medium": self.severity_medium,
                "low": self.severity_low,
                "info": self.severity_info,
            },
            "agent": {
                "total_tool_calls": self.total_tool_calls,
                "total_llm_tokens": self.total_llm_tokens,
                "human_approvals": self.human_approvals,
                "avg_evidence_per_finding": round(self.avg_evidence_per_finding, 1),
                "agent_stats": self.agent_stats,
            },
        }


def compute_metrics(agent_result_outputs: dict[str, Any]) -> ScanMetrics:
    """Build ScanMetrics from an Orchestrator's result outputs."""
    ev_stats = agent_result_outputs.get("evidence_stats", {})
    findings = agent_result_outputs.get("findings", [])
    a_stats = agent_result_outputs.get("agent_stats", [])

    m = ScanMetrics(
        routes_discovered=agent_result_outputs.get("routes_discovered", 0),
        forms_discovered=agent_result_outputs.get("forms_discovered", 0),
        total_findings_raw=ev_stats.get("total_raw", 0),
        total_findings_deduped=ev_stats.get("after_dedup", 0),
        total_confirmed=ev_stats.get("confirmed", 0),
        total_needs_review=ev_stats.get("needs_review", 0),
        total_tool_calls=sum(a.get("tool_calls", 0) for a in a_stats),
        agent_stats=a_stats,
    )

    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical":
            m.severity_critical += 1
        elif sev == "high":
            m.severity_high += 1
        elif sev == "medium":
            m.severity_medium += 1
        elif sev == "low":
            m.severity_low += 1
        else:
            m.severity_info += 1

    return m
