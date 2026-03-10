"""Simulated scan results for MVP demonstration.

Generates realistic WSTG-aligned findings when agents execute against a target.
In production, these come from actual tool execution; for MVP we simulate
a representative set of findings to demonstrate the full pipeline.
"""

import random
from dataclasses import dataclass

FINDING_TEMPLATES = [
    {
        "title": "Missing HTTP Strict-Transport-Security Header",
        "category": "Security Misconfiguration",
        "wstg_refs": ["WSTG-CONF-07"],
        "asvs_refs": ["V14.4.1"],
        "severity": "medium",
        "confidence": 0.95,
        "description": (
            "The application does not set the Strict-Transport-Security header, "
            "allowing potential downgrade attacks. Recommend adding "
            "'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        "agent": "recon",
    },
    {
        "title": "Missing Content-Security-Policy Header",
        "category": "Security Misconfiguration",
        "wstg_refs": ["WSTG-CONF-12"],
        "asvs_refs": ["V14.4.3"],
        "severity": "medium",
        "confidence": 0.90,
        "description": (
            "No Content-Security-Policy header detected. This increases "
            "the risk of XSS attacks. Recommend implementing a strict CSP policy."
        ),
        "agent": "recon",
    },
    {
        "title": "Cookie Without Secure Flag",
        "category": "Session Management",
        "wstg_refs": ["WSTG-SESS-02"],
        "asvs_refs": ["V3.4.1"],
        "severity": "medium",
        "confidence": 0.92,
        "description": (
            "Session cookie is set without the 'Secure' flag, meaning it can "
            "be transmitted over unencrypted HTTP connections."
        ),
        "agent": "authz",
    },
    {
        "title": "Cookie Without HttpOnly Flag",
        "category": "Session Management",
        "wstg_refs": ["WSTG-SESS-02"],
        "asvs_refs": ["V3.4.2"],
        "severity": "low",
        "confidence": 0.95,
        "description": (
            "Session cookie lacks the 'HttpOnly' flag, making it accessible "
            "to JavaScript and vulnerable to XSS-based session theft."
        ),
        "agent": "authz",
    },
    {
        "title": "Horizontal Privilege Escalation (IDOR)",
        "category": "Access Control",
        "wstg_refs": ["WSTG-ATHZ-04"],
        "asvs_refs": ["V4.1.2"],
        "severity": "high",
        "confidence": 0.85,
        "description": (
            "User A can access User B's resources by modifying the object ID "
            "in the request. The endpoint /api/users/{id}/profile does not "
            "verify ownership before returning data."
        ),
        "agent": "authz",
    },
    {
        "title": "Reflected XSS in Search Parameter",
        "category": "Input Validation",
        "wstg_refs": ["WSTG-INPV-01"],
        "asvs_refs": ["V5.3.3"],
        "severity": "high",
        "confidence": 0.88,
        "description": (
            "The 'q' parameter in /search is reflected in the response without "
            "proper encoding. Payload <script>alert(1)</script> executes in the "
            "browser context."
        ),
        "agent": "input",
    },
    {
        "title": "SQL Injection in Login Form",
        "category": "Input Validation",
        "wstg_refs": ["WSTG-INPV-05"],
        "asvs_refs": ["V5.3.4"],
        "severity": "critical",
        "confidence": 0.92,
        "description": (
            "The username field in the login form is vulnerable to SQL injection. "
            "Payload admin' OR '1'='1 bypasses authentication. "
            "The application uses string concatenation instead of parameterized queries."
        ),
        "agent": "input",
    },
    {
        "title": "Verbose Error Messages Expose Stack Trace",
        "category": "Error Handling",
        "wstg_refs": ["WSTG-ERRH-01"],
        "asvs_refs": ["V7.4.1"],
        "severity": "low",
        "confidence": 0.98,
        "description": (
            "Application returns detailed stack traces and internal paths "
            "in error responses. This reveals framework version, file paths, "
            "and database schema information."
        ),
        "agent": "recon",
    },
    {
        "title": "Weak Password Policy",
        "category": "Authentication",
        "wstg_refs": ["WSTG-ATHN-07"],
        "asvs_refs": ["V2.1.1"],
        "severity": "medium",
        "confidence": 0.90,
        "description": (
            "The application accepts passwords as short as 4 characters with "
            "no complexity requirements. Recommend enforcing minimum 8 characters "
            "with mixed case, numbers, and symbols."
        ),
        "agent": "authz",
    },
    {
        "title": "Rate Limiting Not Enforced on Login",
        "category": "Business Logic",
        "wstg_refs": ["WSTG-BUSL-05"],
        "asvs_refs": ["V11.1.4"],
        "severity": "medium",
        "confidence": 0.87,
        "description": (
            "No rate limiting on the /api/auth/login endpoint. An attacker "
            "can perform unlimited brute-force attempts without being blocked."
        ),
        "agent": "bizlogic",
    },
    {
        "title": "Payment Flow Step Bypass",
        "category": "Business Logic",
        "wstg_refs": ["WSTG-BUSL-01"],
        "asvs_refs": ["V11.1.1"],
        "severity": "critical",
        "confidence": 0.75,
        "description": (
            "The checkout process can be bypassed by directly POSTing to "
            "/api/orders/confirm without completing the payment step. "
            "Server-side validation of the payment state is missing."
        ),
        "agent": "bizlogic",
    },
    {
        "title": "Missing X-Frame-Options Header",
        "category": "Security Misconfiguration",
        "wstg_refs": ["WSTG-CONF-07"],
        "asvs_refs": ["V14.4.7"],
        "severity": "low",
        "confidence": 0.97,
        "description": (
            "X-Frame-Options header is not set. The application pages can "
            "be embedded in iframes, enabling potential clickjacking attacks."
        ),
        "agent": "recon",
    },
    {
        "title": "JWT Token Never Expires",
        "category": "Session Management",
        "wstg_refs": ["WSTG-SESS-06"],
        "asvs_refs": ["V3.5.3"],
        "severity": "high",
        "confidence": 0.82,
        "description": (
            "JWT tokens issued by the application have no expiration ('exp') claim. "
            "Once leaked, tokens remain valid indefinitely."
        ),
        "agent": "authz",
    },
]


@dataclass
class SimulatedFinding:
    title: str
    category: str
    wstg_refs: list[str]
    asvs_refs: list[str]
    severity: str
    confidence: float
    description: str
    agent: str


def generate_findings(depth: str = "standard") -> list[SimulatedFinding]:
    """Generate a set of simulated findings based on scan depth."""
    if depth == "quick":
        count = random.randint(3, 5)
    elif depth == "deep":
        count = random.randint(8, len(FINDING_TEMPLATES))
    else:
        count = random.randint(5, 9)

    selected = random.sample(FINDING_TEMPLATES, min(count, len(FINDING_TEMPLATES)))
    return [
        SimulatedFinding(
            title=f["title"],
            category=f["category"],
            wstg_refs=f["wstg_refs"],
            asvs_refs=f["asvs_refs"],
            severity=f["severity"],
            confidence=round(f["confidence"] + random.uniform(-0.05, 0.05), 2),
            description=f["description"],
            agent=f["agent"],
        )
        for f in selected
    ]
