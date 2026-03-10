"""Detection priority matrix per PRD §8.1.

P0 Core    — Must test first (authentication, authorization, session, input, error, config)
P1 Important — Second pass (business logic, file upload, OAuth, rate limiting)
P2 Future  — Deferred (GraphQL, multi-tenant, WebSocket, SPA deep state)
"""


PRIORITY_MATRIX: list[dict[str, str]] = [
    {"priority": "P0", "domain": "Authentication Baseline", "standard": "WSTG-ATHN"},
    {"priority": "P0", "domain": "Authorization / Object Access Control", "standard": "WSTG-ATHZ"},
    {"priority": "P0", "domain": "Session / Cookie / JWT Baseline", "standard": "WSTG-SESS"},
    {"priority": "P0", "domain": "Common Input Point Anomaly Handling", "standard": "WSTG-INPV"},
    {"priority": "P0", "domain": "Error Information Disclosure", "standard": "WSTG-ERRH"},
    {"priority": "P0", "domain": "Basic Security Headers / Configuration", "standard": "WSTG-CONF"},
    {"priority": "P1", "domain": "Business Logic Bypass", "standard": "WSTG-BUSL"},
    {"priority": "P1", "domain": "File Upload", "standard": "WSTG-BUSL"},
    {"priority": "P1", "domain": "Password Reset / Recovery", "standard": "WSTG-ATHN"},
    {"priority": "P1", "domain": "OAuth / OIDC Flow Validation", "standard": "WSTG-ATHN"},
    {"priority": "P1", "domain": "Concurrency & Rate Limiting", "standard": "WSTG-BUSL"},
    {"priority": "P2", "domain": "GraphQL", "standard": "WSTG-INPV"},
    {"priority": "P2", "domain": "Multi-tenant Isolation", "standard": "WSTG-ATHZ"},
    {"priority": "P2", "domain": "WebSocket", "standard": "WSTG-INPV"},
    {"priority": "P2", "domain": "SPA Deep State Coverage", "standard": "WSTG-CLNT"},
]


def get_domains_for_priority(priority: str) -> list[dict[str, str]]:
    return [p for p in PRIORITY_MATRIX if p["priority"] == priority]


def get_all_priorities() -> list[dict[str, str]]:
    return list(PRIORITY_MATRIX)
