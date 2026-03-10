"""Scope Guard — validates all requests stay within the authorized scope.

Enforces:
- Target host whitelist
- Rejects private/reserved IP ranges
- Redirect scope enforcement
- Action risk-level gating
"""

import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class ScopeViolationError(Exception):
    pass


class ScopeGuard:
    def __init__(self, allowed_hosts: list[str], max_risk_level: int = 1) -> None:
        self.allowed_hosts = set(allowed_hosts)
        self.max_risk_level = max_risk_level

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if hostname in self.allowed_hosts:
            return

        try:
            addr = ipaddress.ip_address(hostname)
            for net in PRIVATE_NETWORKS:
                if addr in net:
                    raise ScopeViolationError(f"Blocked private/reserved address: {hostname}")
        except ValueError:
            pass

        raise ScopeViolationError(
            f"Host '{hostname}' is not in allowed scope: {self.allowed_hosts}"
        )

    def check_risk_level(self, level: int) -> None:
        if level > self.max_risk_level:
            raise ScopeViolationError(
                f"Action risk level {level} exceeds maximum allowed {self.max_risk_level}"
            )

    def validate_redirect(self, original_url: str, redirect_url: str) -> None:
        orig_host = urlparse(original_url).hostname
        redir_host = urlparse(redirect_url).hostname
        if redir_host and redir_host not in self.allowed_hosts:
            logger.warning(
                "Redirect from %s to %s blocked (out of scope)", orig_host, redir_host
            )
            raise ScopeViolationError(
                f"Redirect to '{redir_host}' is outside allowed scope"
            )
