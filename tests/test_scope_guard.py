"""Tests for the scope guard — the security boundary of VulnHunter."""

import pytest

from vulnhunter.tools.scope_guard import ScopeGuard, ScopeViolationError


class TestScopeGuard:
    def setup_method(self) -> None:
        self.guard = ScopeGuard(
            allowed_hosts=["app.example.com", "api.example.com"],
            max_risk_level=1,
        )

    def test_allowed_host_passes(self) -> None:
        self.guard.check_url("https://app.example.com/login")

    def test_disallowed_host_blocked(self) -> None:
        with pytest.raises(ScopeViolationError, match="not in allowed scope"):
            self.guard.check_url("https://evil.com/steal")

    def test_private_ip_blocked(self) -> None:
        with pytest.raises(ScopeViolationError, match="private/reserved"):
            self.guard.check_url("http://10.0.0.1/admin")

    def test_localhost_blocked(self) -> None:
        with pytest.raises(ScopeViolationError, match="private/reserved"):
            self.guard.check_url("http://127.0.0.1:8080/")

    def test_link_local_blocked(self) -> None:
        with pytest.raises(ScopeViolationError, match="private/reserved"):
            self.guard.check_url("http://169.254.169.254/metadata")

    def test_risk_level_within_limit(self) -> None:
        self.guard.check_risk_level(0)
        self.guard.check_risk_level(1)

    def test_risk_level_exceeds_limit(self) -> None:
        with pytest.raises(ScopeViolationError, match="exceeds maximum"):
            self.guard.check_risk_level(2)

    def test_redirect_in_scope(self) -> None:
        self.guard.validate_redirect(
            "https://app.example.com/a",
            "https://api.example.com/b",
        )

    def test_redirect_out_of_scope(self) -> None:
        with pytest.raises(ScopeViolationError, match="outside allowed scope"):
            self.guard.validate_redirect(
                "https://app.example.com/login",
                "https://evil.com/phish",
            )
