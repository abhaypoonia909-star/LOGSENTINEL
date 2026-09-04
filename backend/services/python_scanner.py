"""Python source code vulnerability scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass

from services.security_models import VulnerabilityFinding


RULES = [
    {
        "type": "Code Injection",
        "pattern": r"\beval\s*\(",
        "severity": "Critical",
        "description": "Use of eval() allows arbitrary code execution.",
        "recommendation": "Remove eval(); use safe parsing such as ast.literal_eval for data.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-94",
    },
    {
        "type": "Code Injection",
        "pattern": r"\bexec\s*\(",
        "severity": "Critical",
        "description": "Use of exec() can execute attacker-controlled code.",
        "recommendation": "Refactor to explicit logic; never exec untrusted input.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-94",
    },
    {
        "type": "Command Injection",
        "pattern": r"\bos\.system\s*\(",
        "severity": "Critical",
        "description": "os.system() invokes a shell and is unsafe with user input.",
        "recommendation": "Use subprocess with shell=False and argument lists.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Command Injection",
        "pattern": r"\bsubprocess\.(call|Popen)\s*\([^)]*shell\s*=\s*True",
        "severity": "Critical",
        "description": "subprocess with shell=True enables command injection.",
        "recommendation": "Set shell=False and pass arguments as a list.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Command Injection",
        "pattern": r"\bsubprocess\.run\s*\([^)]*shell\s*=\s*True",
        "severity": "Critical",
        "description": "subprocess.run(shell=True) is vulnerable to injection.",
        "recommendation": "Use shell=False and validate all external input.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Insecure Deserialization",
        "pattern": r"\bpickle\.loads\s*\(",
        "severity": "Critical",
        "description": "pickle.loads() can deserialize malicious objects.",
        "recommendation": "Avoid pickle for untrusted data; use JSON or signed formats.",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
    },
    {
        "type": "Hardcoded Credentials",
        "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]",
        "severity": "High",
        "description": "Hardcoded password detected in source code.",
        "recommendation": "Load secrets from environment variables or a vault.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
    },
    {
        "type": "Hardcoded API Key",
        "pattern": r"(?i)(api[_-]?key|secret[_-]?key|token)\s*=\s*['\"][^'\"]{8,}['\"]",
        "severity": "Critical",
        "description": "Hardcoded API key or secret detected.",
        "recommendation": "Rotate the key and store it outside source control.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-798",
    },
    {
        "type": "Weak Cryptography",
        "pattern": r"(?i)\b(md5|sha1|DES|RC4)\b",
        "severity": "Medium",
        "description": "Weak or deprecated cryptographic algorithm referenced.",
        "recommendation": "Use SHA-256+, bcrypt, Argon2, or AES-GCM as appropriate.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-327",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(execute\s*\(\s*f['\"]|cursor\.execute\s*\(\s*['\"].*\+|SELECT\s+.+\+\s*\w+)",
        "severity": "Critical",
        "description": "Unsafe SQL query construction detected.",
        "recommendation": "Use parameterized queries or ORM bindings.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
]


class PythonScanner:
    def scan(self, content: str, filename: str = "unknown.py") -> list[VulnerabilityFinding]:
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