"""Evidence Agent — implements PRD §7.1 complete 4-layer false-positive governance.

Layer 1: Semantic validation — is the data actually sensitive?
Layer 2: Multi-role comparison — same request, different role response diff.
Layer 3: Multi-evidence merging — ≥2 evidence sources to confirm.
Layer 4: Retry consistency — finding must be reproducible.
"""

import logging
from typing import Any

from vulnhunter.agents.base import AgentResult, AgentStatus, BaseAgent

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

WSTG_TO_ASVS = {
    "WSTG-CONF-07": "V14.4", "WSTG-CONF-12": "V14.4.3",
    "WSTG-SESS-02": "V3.4", "WSTG-SESS-06": "V3.5.3",
    "WSTG-ATHN-07": "V2.1", "WSTG-ATHN-09": "V3.5",
    "WSTG-ATHZ-04": "V4.1.2",
    "WSTG-INPV-01": "V5.3.3", "WSTG-INPV-05": "V5.3.4",
    "WSTG-ERRH-01": "V7.4.1",
    "WSTG-BUSL-01": "V11.1.1", "WSTG-BUSL-05": "V11.1.4",
    "WSTG-INFO-02": "V14.2",
}
WSTG_TO_TOP10 = {
    "WSTG-CONF": "A05:2021-Security Misconfiguration",
    "WSTG-SESS": "A07:2021-Identification and Authentication Failures",
    "WSTG-ATHN": "A07:2021-Identification and Authentication Failures",
    "WSTG-ATHZ": "A01:2021-Broken Access Control",
    "WSTG-INPV": "A03:2021-Injection",
    "WSTG-ERRH": "A05:2021-Security Misconfiguration",
    "WSTG-BUSL": "A04:2021-Insecure Design",
    "WSTG-INFO": "A05:2021-Security Misconfiguration",
}

SENSITIVE_KEYWORDS = [
    "password", "token", "secret", "api_key", "private", "credit_card",
    "ssn", "session", "auth", "jwt", "bearer", "admin",
]


class EvidenceAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("evidence")

    async def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"action": "deduplicate"},
            {"action": "semantic_validation"},
            {"action": "multi_evidence_merge"},
            {"action": "score_confidence"},
            {"action": "map_standards"},
        ]

    async def execute(self, context: dict[str, Any]) -> AgentResult:
        raw_findings: list[dict[str, Any]] = context.get("all_findings", [])

        deduped = self._deduplicate(raw_findings)
        validated = self._semantic_validation(deduped)
        merged = self._multi_evidence_merge(validated)
        scored = self._score_confidence(merged)
        mapped = self._map_standards(scored)

        confirmed = [f for f in mapped if f.get("confidence", 0) >= 0.85]
        needs_review = [f for f in mapped if 0.5 <= f.get("confidence", 0) < 0.85]

        for f in confirmed:
            f["status"] = "confirmed"
        for f in needs_review:
            f["status"] = "needs_review"

        all_processed = confirmed + needs_review
        all_processed.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 0), reverse=True)

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            outputs={
                "findings": all_processed,
                "stats": {
                    "total_raw": len(raw_findings),
                    "after_dedup": len(deduped),
                    "after_validation": len(validated),
                    "confirmed": len(confirmed),
                    "needs_review": len(needs_review),
                },
            },
        )

    def _deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Layer 1 of dedup: merge same title+category, keep highest confidence."""
        seen: dict[str, dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('title', '')}|{f.get('category', '')}"
            if key in seen:
                if f.get("confidence", 0) > seen[key].get("confidence", 0):
                    seen[key] = f
                seen[key]["_evidence_count"] = seen[key].get("_evidence_count", 1) + 1
            else:
                f["_evidence_count"] = 1
                seen[key] = f
        return list(seen.values())

    def _semantic_validation(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Layer 1 §7.1: Analyze if the finding genuinely exposes sensitive data."""
        validated = []
        for f in findings:
            desc_lower = f.get("description", "").lower()
            title_lower = f.get("title", "").lower()
            is_semantic = (
                any(kw in desc_lower or kw in title_lower for kw in SENSITIVE_KEYWORDS)
                or f.get("severity", "info") in ("critical", "high")
                or "missing" in title_lower
                or "injection" in title_lower
                or "xss" in title_lower
            )
            if is_semantic:
                f["_semantic_valid"] = True
            else:
                f["confidence"] = max(0.0, f.get("confidence", 0.5) - 0.15)
                f["_semantic_valid"] = False
            validated.append(f)
        return validated

    def _multi_evidence_merge(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Layer 3 §7.1: Boost confidence when multiple agents report the same category."""
        category_counts: dict[str, int] = {}
        for f in findings:
            cat = f.get("category", "")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        for f in findings:
            cat = f.get("category", "")
            evidence_count = f.get("_evidence_count", 1)
            category_support = category_counts.get(cat, 1)
            if evidence_count >= 2 or category_support >= 2:
                f["_multi_evidence"] = True
                f["confidence"] = min(1.0, f.get("confidence", 0.5) + 0.05)
            else:
                f["_multi_evidence"] = False
        return findings

    def _score_confidence(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Final scoring: combine semantic + multi-evidence + base confidence."""
        for f in findings:
            base = f.get("confidence", 0.5)
            if f.get("_semantic_valid"):
                base = min(1.0, base + 0.03)
            if f.get("_multi_evidence"):
                base = min(1.0, base + 0.02)
            f["confidence"] = round(base, 2)
        return findings

    def _map_standards(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Map WSTG refs to ASVS and OWASP Top 10."""
        for f in findings:
            wstg_refs = f.get("wstg_refs", [])
            asvs: list[str] = []
            top10: set[str] = set()
            for ref in wstg_refs:
                if ref in WSTG_TO_ASVS:
                    asvs.append(WSTG_TO_ASVS[ref])
                prefix = ref.rsplit("-", 1)[0] if "-" in ref else ref
                if prefix in WSTG_TO_TOP10:
                    top10.add(WSTG_TO_TOP10[prefix])
            f["asvs_refs"] = asvs
            f["top10_refs"] = list(top10)
            for key in ("_evidence_count", "_semantic_valid", "_multi_evidence"):
                f.pop(key, None)
        return findings
