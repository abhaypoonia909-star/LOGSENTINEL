"""JavaScript / TypeScript source code vulnerability scanner."""

from __future__ import annotations

import re

from services.security_models import VulnerabilityFinding


RULES = [
    {
        "type": "Code Injection",
        "pattern": r"\beval\s*\(",
        "severity": "Critical",
        "description": "eval() executes arbitrary JavaScript.",
        "recommendation": "Use JSON.parse or safe templating instead of eval.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-94",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"\.innerHTML\s*=",
        "severity": "High",
        "description": "Direct innerHTML assignment can lead to DOM XSS.",
        "recommendation": "Use textContent or sanitize with DOMPurify.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"\bdocument\.write\s*\(",
        "severity": "High",
        "description": "document.write() can inject unsafe HTML.",
        "recommendation": "Use DOM APIs and encode all dynamic content.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Sensitive Data Exposure",
        "pattern": r"(?i)localStorage\.(setItem|getItem)\s*\(\s*['\"](token|jwt|auth|session)",
        "severity": "High",
        "description": "Authentication token stored in localStorage.",
        "recommendation": "Use HttpOnly secure cookies for session tokens.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-922",
    },
    {
        "type": "DOM-based XSS",
        "pattern": r"(location\.(hash|search|href)|document\.URL).*innerHTML",
        "severity": "Critical",
        "description": "URL/DOM source flows into innerHTML sink.",
        "recommendation": "Sanitize URL parameters before rendering in the DOM.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Insecure Request",
        "pattern": r"fetch\s*\(\s*[^)]*\+",
        "severity": "Medium",
        "description": "Dynamic fetch URL built via string concatenation.",
        "recommendation": "Validate URLs against an allowlist; use URL API.",
        "owasp": "A10:2021 – Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
    },
    {
        "type": "Insecure Request",
        "pattern": r"fetch\s*\(\s*['\"]http://",
        "severity": "Medium",
        "description": "Plain HTTP fetch may expose data in transit.",
        "recommendation": "Use HTTPS for all API requests.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-319",
    },
]


class JavaScriptScanner:
    def scan(self, content: str, filename: str = "unknown.js") -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if re.search(rule["pattern"], line):
                    findings.append(VulnerabilityFinding(
                        line=line_no,
                        severity=rule["severity"],
                        type=rule["type"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        owasp=rule["owasp"],
                        cwe=rule["cwe"],
                        file=filename,
                        snippet=line.strip()[:200],
                    ))
        return findings