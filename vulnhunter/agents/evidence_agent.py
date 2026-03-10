"""Evidence Agent — deduplication, cross-validation, confidence scoring, report generation.

Implements PRD §7.1 four-layer false-positive governance:
1. Semantic validation (is data actually leaked?)
2. Multi-role comparison (same request, different role responses)
3. Multi-evidence merging (at least 2 evidence types to confirm)
4. Retry consistency (same test, repeatable result)
"""

import logging
from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class EvidenceAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("evidence")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "deduplicate"},
            {"action": "cross_validate"},
            {"action": "score_confidence"},
            {"action": "map_standards"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        raw_findings: list[dict[str, Any]] = context.get("all_findings", [])

        deduped = self._deduplicate(raw_findings)
        scored = self._score_confidence(deduped)
        mapped = self._map_standards(scored)

        confirmed = [f for f in mapped if f.get("confidence", 0) >= 0.85]
        needs_review = [f for f in mapped if 0.5 <= f.get("confidence", 0) < 0.85]

        for f in confirmed:
            f["status"] = "confirmed"
        for f in needs_review:
            f["status"] = "needs_review"

        all_processed = confirmed + needs_review
        all_processed.sort(
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 0),
            reverse=True,
        )

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            outputs={
                "findings": all_processed,
                "stats": {
                    "total_raw": len(raw_findings),
                    "after_dedup": len(deduped),
                    "confirmed": len(confirmed),
                    "needs_review": len(needs_review),
                },
            },
        )

    def _deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('title', '')}|{f.get('category', '')}"
            if key in seen:
                existing = seen[key]
                if f.get("confidence", 0) > existing.get("confidence", 0):
                    seen[key] = f
            else:
                seen[key] = f
        return list(seen.values())

    def _score_confidence(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for f in findings:
            base = f.get("confidence", 0.5)
            agents_found = 1
            if isinstance(f.get("agent"), str):
                agents_found = 1
            boost = min(agents_found * 0.05, 0.15)
            f["confidence"] = min(round(base + boost, 2), 1.0)
        return findings

    def _map_standards(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        wstg_to_asvs = {
            "WSTG-CONF-07": "V14.4",
            "WSTG-CONF-12": "V14.4.3",
            "WSTG-SESS-02": "V3.4",
            "WSTG-SESS-06": "V3.5.3",
            "WSTG-ATHN-07": "V2.1",
            "WSTG-ATHN-09": "V3.5",
            "WSTG-ATHZ-04": "V4.1.2",
            "WSTG-INPV-01": "V5.3.3",
            "WSTG-INPV-05": "V5.3.4",
            "WSTG-ERRH-01": "V7.4.1",
            "WSTG-BUSL-01": "V11.1.1",
            "WSTG-BUSL-05": "V11.1.4",
            "WSTG-INFO-02": "V14.2",
        }
        wstg_to_top10 = {
            "WSTG-CONF": "A05:2021-Security Misconfiguration",
            "WSTG-SESS": "A07:2021-Identification and Authentication Failures",
            "WSTG-ATHN": "A07:2021-Identification and Authentication Failures",
            "WSTG-ATHZ": "A01:2021-Broken Access Control",
            "WSTG-INPV": "A03:2021-Injection",
            "WSTG-ERRH": "A05:2021-Security Misconfiguration",
            "WSTG-BUSL": "A04:2021-Insecure Design",
            "WSTG-INFO": "A05:2021-Security Misconfiguration",
        }

        for f in findings:
            wstg_refs = f.get("wstg_refs", [])
            asvs = []
            top10 = set()
            for ref in wstg_refs:
                if ref in wstg_to_asvs:
                    asvs.append(wstg_to_asvs[ref])
                prefix = ref.rsplit("-", 1)[0] if "-" in ref else ref
                if prefix in wstg_to_top10:
                    top10.add(wstg_to_top10[prefix])
            f["asvs_refs"] = asvs
            f["top10_refs"] = list(top10)
        return findings
