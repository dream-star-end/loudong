"""L0-L3 action risk classification per PRD §5.1.

L0 Safe    — read-only, no side effects → auto-execute
L1 Low     — single param light mutation → auto-execute, rate-limited
L2 Medium  — may change state           → needs approval or pre-auth
L3 High    — may affect availability     → disabled by default
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

DANGEROUS_PATTERNS = [
    "drop", "truncate", "delete", "destroy", "shutdown", "admin/reset",
    "bulk", "batch", "import", "migrate",
]

UPLOAD_PATTERNS = ["upload", "file", "attachment", "import"]


@dataclass
class ActionClassification:
    level: int
    label: str
    auto_execute: bool
    reason: str


def classify_action(
    method: str,
    url: str,
    has_body: bool = False,
    is_mutation: bool = False,
    payload_size: int = 0,
) -> ActionClassification:
    """Classify an HTTP action into risk levels L0-L3."""
    method_upper = method.upper()
    url_lower = url.lower()

    if any(p in url_lower for p in DANGEROUS_PATTERNS):
        return ActionClassification(3, "L3-High", False, "dangerous URL pattern")

    if any(p in url_lower for p in UPLOAD_PATTERNS) and method_upper in STATE_CHANGE_METHODS:
        return ActionClassification(2, "L2-Medium", False, "file upload endpoint")

    if method_upper in STATE_CHANGE_METHODS and is_mutation:
        return ActionClassification(2, "L2-Medium", False, "state-changing mutation")

    if method_upper in STATE_CHANGE_METHODS:
        return ActionClassification(1, "L1-Low", True, "state-change method")

    if method_upper in SAFE_METHODS:
        return ActionClassification(0, "L0-Safe", True, "read-only request")

    return ActionClassification(1, "L1-Low", True, "unknown method, default low")
