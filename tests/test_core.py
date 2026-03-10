"""Tests for core infrastructure — manifest, rate limiter, audit, action classifier, HITL, memory."""


import pytest

from vulnhunter.core.action_classifier import classify_action
from vulnhunter.core.audit import AuditLogger
from vulnhunter.core.hitl import ApprovalQueue, ApprovalStatus
from vulnhunter.core.manifest import EngagementManifest
from vulnhunter.core.memory import KnowledgeBase, ShortTermMemory, TaskMemory
from vulnhunter.core.rate_limiter import RateLimiter
from vulnhunter.core.report import generate_dev_report


class TestManifest:
    def test_from_dict(self) -> None:
        raw = {
            "target": {"hosts": ["app.example.com"]},
            "scope": {"allow_login": True, "allow_state_change": "low"},
            "roles": [{"name": "admin", "credentials": {"username": "a", "password": "b"}}],
            "testing_profile": {"depth": "deep", "standards": ["WSTG"]},
        }
        m = EngagementManifest.from_dict(raw)
        assert m.hosts == ["app.example.com"]
        assert m.scope.allow_login is True
        assert m.roles[0].name == "admin"
        assert m.testing_profile.depth == "deep"
        assert m.max_risk_level == 1

    def test_from_target(self) -> None:
        m = EngagementManifest.from_target("Test", ["h1.com"], ["guest", "admin"])
        assert len(m.roles) == 2
        assert m.hosts == ["h1.com"]


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire(self) -> None:
        rl = RateLimiter(rate=100.0, burst=10)
        for _ in range(5):
            await rl.acquire()


class TestAudit:
    def test_log_and_query(self) -> None:
        al = AuditLogger()
        al.log("recon", "http", "GET", "http://test.com", 0, 200, 15.0)
        al.log("authz", "http", "POST", "http://test.com/login", 1, 401, 25.0)
        assert len(al.entries) == 2
        recon_only = al.query(agent="recon")
        assert len(recon_only) == 1


class TestActionClassifier:
    def test_safe_get(self) -> None:
        c = classify_action("GET", "http://example.com/page")
        assert c.level == 0
        assert c.auto_execute is True

    def test_post_low(self) -> None:
        c = classify_action("POST", "http://example.com/api/data")
        assert c.level == 1

    def test_dangerous_high(self) -> None:
        c = classify_action("POST", "http://example.com/admin/reset")
        assert c.level == 3
        assert c.auto_execute is False


class TestHITL:
    def test_submit_and_approve(self) -> None:
        q = ApprovalQueue()
        req = q.submit("input", "POST", "http://x.com/upload", 2, "file upload")
        assert req.status == ApprovalStatus.PENDING
        assert len(q.list_pending()) == 1
        q.approve(req.id)
        assert req.status == ApprovalStatus.APPROVED
        assert len(q.list_pending()) == 0

    def test_reject(self) -> None:
        q = ApprovalQueue()
        req = q.submit("input", "DELETE", "http://x.com/data", 3)
        q.reject(req.id)
        assert req.status == ApprovalStatus.REJECTED


class TestMemory:
    def test_task_memory(self) -> None:
        tm = TaskMemory()
        tm.store("routes", [{"path": "/api"}])
        assert tm.retrieve("routes") == [{"path": "/api"}]
        assert "routes" in tm.all()

    def test_knowledge_base(self) -> None:
        kb = KnowledgeBase()
        assert "WSTG-CONF-07" in kb.wstg_templates
        matches = kb.match_framework({"server": "Werkzeug/3.0"}, "")
        assert "flask" in matches

    @pytest.mark.asyncio
    async def test_short_term_local(self) -> None:
        stm = ShortTermMemory()
        await stm.set("test_key", {"a": 1})
        val = await stm.get("test_key")
        assert val == {"a": 1}


class TestReport:
    def test_generate_dev_report(self) -> None:
        html = generate_dev_report(
            "Test App",
            ["app.test.com"],
            [
                {"title": "XSS", "category": "Input Validation", "severity": "high",
                 "confidence": 0.9, "description": "XSS found", "wstg_refs": ["WSTG-INPV-01"],
                 "asvs_refs": ["V5.3.3"], "top10_refs": ["A03"], "status": "confirmed"},
            ],
        )
        assert "VulnHunter" in html
        assert "XSS" in html
        assert "WSTG-INPV-01" in html
