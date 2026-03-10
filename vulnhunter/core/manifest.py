"""Engagement manifest — parsed from YAML, drives scope and agent behaviour.

Example engagement_manifest.yaml:
    target:
      hosts: [app.example.com, api.example.com]
    scope:
      allow_login: true
      allow_file_upload: false
      allow_state_change: low
      allow_destructive_actions: false
    roles:
      - name: guest
      - name: user
        credentials: {username: test, password: test123}
      - name: admin
        credentials: {username: admin, password: admin123}
    testing_profile:
      depth: standard          # quick | standard | deep
      standards: [WSTG, ASVS, OWASP_TOP10_2025]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class RoleConfig:
    name: str
    credentials: dict[str, str] = field(default_factory=dict)


@dataclass
class ScopeConfig:
    allow_login: bool = True
    allow_file_upload: bool = False
    allow_state_change: str = "low"
    allow_destructive_actions: bool = False


@dataclass
class TestingProfile:
    depth: str = "standard"
    standards: list[str] = field(default_factory=lambda: ["WSTG", "ASVS", "OWASP_TOP10_2025"])


@dataclass
class EngagementManifest:
    hosts: list[str] = field(default_factory=list)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    roles: list[RoleConfig] = field(default_factory=list)
    testing_profile: TestingProfile = field(default_factory=TestingProfile)

    @classmethod
    def from_yaml(cls, path: str | Path) -> EngagementManifest:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> EngagementManifest:
        target = raw.get("target", {})
        scope_raw = raw.get("scope", {})
        roles_raw = raw.get("roles", [])
        profile_raw = raw.get("testing_profile", {})

        return cls(
            hosts=target.get("hosts", []),
            scope=ScopeConfig(
                allow_login=scope_raw.get("allow_login", True),
                allow_file_upload=scope_raw.get("allow_file_upload", False),
                allow_state_change=scope_raw.get("allow_state_change", "low"),
                allow_destructive_actions=scope_raw.get("allow_destructive_actions", False),
            ),
            roles=[
                RoleConfig(name=r.get("name", ""), credentials=r.get("credentials", {}))
                for r in roles_raw
            ],
            testing_profile=TestingProfile(
                depth=profile_raw.get("depth", "standard"),
                standards=profile_raw.get("standards", ["WSTG", "ASVS", "OWASP_TOP10_2025"]),
            ),
        )

    @classmethod
    def from_target(cls, name: str, hosts: list[str], roles: list[str], depth: str = "standard") -> EngagementManifest:
        """Build manifest from a Target DB record (for API-driven flows)."""
        return cls(
            hosts=hosts,
            roles=[RoleConfig(name=r) for r in roles],
            testing_profile=TestingProfile(depth=depth),
        )

    @property
    def max_risk_level(self) -> int:
        if self.scope.allow_destructive_actions:
            return 3
        if self.scope.allow_state_change in ("medium", "high"):
            return 2
        return 1
