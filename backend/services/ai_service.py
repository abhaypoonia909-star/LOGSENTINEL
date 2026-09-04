"""
CyberShield AI Security Assistant
Analyzes existing Log Analyzer results and returns structured security guidance.

Backward compatibility:
- AIService.answer(question, analysis_data) still returns:
  explanation, risk, prevention
- Existing /api/ai route continues to work unchanged.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


# ------------------------------------------------------------------
# Knowledge base for general security Q&A (kept for API compatibility)
# ------------------------------------------------------------------
KNOWLEDGE = {
    "sql injection": {
        "explanation": "SQL injection happens when user input is concatenated into SQL queries.",
        "risk": "Attackers can read, modify, or delete database records.",
        "prevention": "Use parameterized queries, ORM bindings, and strict input validation.",
    },
    "brute force": {
        "explanation": "Brute-force attacks repeatedly guess credentials to gain access.",
        "risk": "Successful login can lead to account takeover.",
        "prevention": "Enable rate limiting, MFA, and IP blocking after failed attempts.",
    },
    "port scan": {
        "explanation": "Port scanning probes open services on a host.",
        "risk": "It is often the first step before exploitation.",
        "prevention": "Close unused ports and monitor reconnaissance patterns.",
    },
    "xss": {
        "explanation": "Cross-site scripting injects malicious scripts into web pages.",
        "risk": "Attackers can steal sessions or deface applications.",
        "prevention": "Encode output, use CSP, and sanitize all user input.",
    },
}


# ------------------------------------------------------------------
# Enterprise mapping tables
# ------------------------------------------------------------------
MITRE_BY_CATEGORY = {
    "Brute Force": ["T1110 - Brute Force"],
    "Port Scan": ["T1046 - Network Service Discovery"],
    "Intrusion": ["T1190 - Exploit Public-Facing Application"],
    "Critical Event": ["T1068 - Exploitation for Privilege Escalation"],
    "Malware Indicator": [
        "T1105 - Ingress Tool Transfer",
        "T1059 - Command and Scripting Interpreter",
    ],
    "SQL Injection": ["T1190 - Exploit Public-Facing Application"],
    "Cross-Site Scripting (XSS)": ["T1059.007 - JavaScript"],
    "Directory Traversal": ["T1005 - Data from Local System"],
    "Command Injection": ["T1059 - Command and Scripting Interpreter"],
    "Reverse Shell": [
        "T1059 - Command and Scripting Interpreter",
        "T1071 - Application Layer Protocol",
    ],
    "Suspicious PowerShell": ["T1059.001 - PowerShell"],
    "Web Shell": ["T1505.003 - Web Shell"],
    "Privilege Escalation / Unauthorized Access": [
        "T1068 - Exploitation for Privilege Escalation"
    ],
}

OWASP_BY_CATEGORY = {
    "Brute Force": ["A07:2021 - Identification and Authentication Failures"],
    "Port Scan": ["A05:2021 - Security Misconfiguration"],
    "Intrusion": ["A03:2021 - Injection", "A01:2021 - Broken Access Control"],
    "Critical Event": ["A04:2021 - Insecure Design"],
    "Malware Indicator": ["A08:2021 - Software and Data Integrity Failures"],
    "SQL Injection": ["A03:2021 - Injection"],
    "Cross-Site Scripting (XSS)": ["A03:2021 - Injection"],
    "Directory Traversal": ["A01:2021 - Broken Access Control"],
    "Command Injection": ["A03:2021 - Injection"],
    "Reverse Shell": ["A03:2021 - Injection"],
    "Suspicious PowerShell": ["A03:2021 - Injection"],
    "Web Shell": [
        "A03:2021 - Injection",
        "A08:2021 - Software and Data Integrity Failures",
    ],
    "Privilege Escalation / Unauthorized Access": [
        "A01:2021 - Broken Access Control"
    ],
}


class AIService:
    """AI Security Assistant — Q&A + structured incident analysis."""

    # ==============================================================
    # Existing public API (DO NOT break)
    # ==============================================================
    def answer(self, question: str, analysis_data: dict | None = None) -> dict:
        """
        Backward-compatible method used by routes/ai.py.

        Always returns:
          - explanation
          - risk
          - prevention

        When analysis_data is provided, also includes:
          - ai_analysis (full structured JSON)
        """
        q = (question or "").lower().strip()

        # 1) Knowledge-base Q&A (existing behavior)
        for key, val in KNOWLEDGE.items():
            if key in q:
                result = dict(val)
                if analysis_data:
                    result["ai_analysis"] = self.analyze_security(analysis_data)
                return result

        # 2) Analysis-aware response
        if analysis_data:
            ai_analysis = self.analyze_security(analysis_data)
            score = int(analysis_data.get("risk_score", 0) or 0)
            return {
                "explanation": ai_analysis["executive_ai_summary"],
                "risk": self._risk_label(score),
                "prevention": "; ".join(ai_analysis["recommended_actions"][:3])
                or "Continue monitoring and preserve forensic evidence.",
                "ai_analysis": ai_analysis,
            }

        # 3) Generic fallback (existing behavior)
        return {
            "explanation": "I can explain cybersecurity concepts and LogSentinel analysis results.",
            "risk": "Depends on the threat type and exposure.",
            "prevention": "Apply defense in depth: monitoring, patching, least privilege, and secure coding.",
        }

    # ==============================================================
    # New enterprise analysis API
    # ==============================================================
    def analyze_security(self, analysis_data: dict) -> dict[str, Any]:
        """
        Generate a structured AI security assessment from analyzer output.
        Returns JSON with the 10 required sections.
        """
        analysis_data = analysis_data or {}
        threats = analysis_data.get("threats", []) or []
        risk_score = int(analysis_data.get("risk_score", 0) or 0)
        severity = str(analysis_data.get("severity", "low")).lower()
        confidence = self._confidence_score(analysis_data, threats)

        threat_explanation = self._threat_explanation(analysis_data, threats)
        attack_chain = self._attack_chain_description(analysis_data, threats)
        business_impact = self._business_impact(risk_score, severity, threats)
        actions = self._recommended_actions(analysis_data, threats)
        mitre = self._mitre_techniques(threats)
        owasp = self._owasp_mapping(threats)
        priority = self._incident_priority(risk_score, severity, threats)
        next_steps = self._next_investigation_steps(analysis_data, threats, priority)
        executive = self._executive_ai_summary(
            risk_score, severity, confidence, priority, threats
        )

        return {
            "executive_ai_summary": executive,
            "threat_explanation": threat_explanation,
            "attack_chain_description": attack_chain,
            "business_impact": business_impact,
            "recommended_actions": actions,
            "mitre_attack_techniques": mitre,
            "owasp_top_10_mapping": owasp,
            "confidence_score": confidence,
            "incident_priority": priority,
            "next_investigation_steps": next_steps,
        }

    # ==============================================================
    # Helper functions
    # ==============================================================
    def _risk_label(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Moderate"
        return "Low"

    def _count_by_category(self, threats: list[dict]) -> Counter:
        return Counter(str(t.get("category", "Unknown")) for t in threats)

    def _count_by_severity(self, threats: list[dict]) -> Counter:
        return Counter(str(t.get("severity", "low")).lower() for t in threats)

    def _top_ips(self, analysis_data: dict, threats: list[dict], limit: int = 5) -> list[str]:
        counts = Counter()
        for t in threats:
            ip = t.get("source_ip")
            if ip:
                counts[str(ip)] += 1
        for row in analysis_data.get("brute_force", {}).get("flagged_ips", []) or []:
            ip = row.get("ip_address")
            if ip:
                counts[str(ip)] += int(row.get("attempt_count", 1))
        return [ip for ip, _ in counts.most_common(limit)]

    def _confidence_score(self, analysis_data: dict, threats: list[dict]) -> int:
        """Derive confidence 0–100 from analyzer confidence + signal strength."""
        provided = analysis_data.get("confidence")
        if isinstance(provided, (int, float)):
            return max(0, min(100, int(provided)))

        score = int(analysis_data.get("risk_score", 0) or 0)
        detectors = sum(
            [
                1 if analysis_data.get("brute_force", {}).get("flagged_ips") else 0,
                1 if analysis_data.get("port_scan", {}).get("event_count", 0) else 0,
                1 if analysis_data.get("intrusion", {}).get("event_count", 0) else 0,
                1 if analysis_data.get("critical_events", {}).get("event_count", 0) else 0,
                1 if analysis_data.get("malware", {}).get("event_count", 0) else 0,
            ]
        )
        volume = int(analysis_data.get("stats", {}).get("total_lines", 0) or 0)
        volume_factor = min(volume / 50.0, 1.0)
        confidence = int(min(100, 35 + score * 0.3 + detectors * 8 + volume_factor * 15))
        if not threats and score == 0:
            return 55  # clean log — moderate confidence in "all clear"
        return max(30, confidence)

    def _executive_ai_summary(
        self,
        risk_score: int,
        severity: str,
        confidence: int,
        priority: str,
        threats: list[dict],
    ) -> str:
        if not threats and risk_score < 20:
            return (
                f"AI assessment indicates a low-risk posture (score {risk_score}/100). "
                f"No significant attack patterns were identified. "
                f"Confidence {confidence}%. Incident priority: {priority}."
            )
        cats = self._count_by_category(threats)
        top = ", ".join(f"{k} ({v})" for k, v in cats.most_common(3)) or "mixed threats"
        return (
            f"AI assessment classifies this incident as {severity.upper()} "
            f"(risk {risk_score}/100, confidence {confidence}%). "
            f"Detected {len(threats)} threat events dominated by: {top}. "
            f"Recommended incident priority: {priority}."
        )

    def _threat_explanation(self, analysis_data: dict, threats: list[dict]) -> str:
        bf = len(analysis_data.get("brute_force", {}).get("flagged_ips", []) or [])
        ps = int(analysis_data.get("port_scan", {}).get("event_count", 0) or 0)
        intr = int(analysis_data.get("intrusion", {}).get("event_count", 0) or 0)
        crit = int(analysis_data.get("critical_events", {}).get("event_count", 0) or 0)
        mal = int(analysis_data.get("malware", {}).get("event_count", 0) or 0)

        parts = []
        if bf:
            parts.append(f"{bf} brute-force source IP(s) exceeded failed-login thresholds")
        if ps:
            parts.append(f"{ps} port-scan / reconnaissance indicator(s)")
        if intr:
            parts.append(f"{intr} intrusion pattern(s) (injection, traversal, or unauthorized access)")
        if crit:
            parts.append(f"{crit} critical system event(s)")
        if mal:
            parts.append(f"{mal} malware / payload indicator(s)")

        if not parts:
            return (
                "No high-signal threat categories were triggered. "
                "Observed activity appears routine or below detection thresholds."
            )

        titles = [str(t.get("title") or t.get("category") or "Threat") for t in threats[:5]]
        detail = "; ".join(titles)
        return (
            "The analyzer identified the following threat signals: "
            + "; ".join(parts)
            + f". Notable findings include: {detail}."
        )

    def _attack_chain_description(self, analysis_data: dict, threats: list[dict]) -> str:
        """Describe a likely kill-chain based on which detectors fired."""
        stages: list[str] = []

        if analysis_data.get("port_scan", {}).get("event_count", 0):
            stages.append("Reconnaissance (port scanning / service discovery)")
        if analysis_data.get("brute_force", {}).get("flagged_ips"):
            stages.append("Initial Access attempt via credential brute force")
        if analysis_data.get("intrusion", {}).get("event_count", 0):
            stages.append("Exploitation / intrusion attempts against the application or host")
        if analysis_data.get("malware", {}).get("event_count", 0):
            stages.append("Payload delivery or malware indicators (webshell, miner, reverse shell)")
        if analysis_data.get("critical_events", {}).get("event_count", 0):
            stages.append("Privilege escalation or critical system compromise signals")

        if not stages:
            return (
                "No multi-stage attack chain is evident from the current log evidence. "
                "Continue monitoring for reconnaissance and authentication anomalies."
            )

        chain = " → ".join(stages)
        ips = self._top_ips(analysis_data, threats, limit=3)
        ip_note = f" Primary source IPs of interest: {', '.join(ips)}." if ips else ""
        return f"Likely attack progression: {chain}.{ip_note}"

    def _business_impact(self, risk_score: int, severity: str, threats: list[dict]) -> str:
        sev_counts = self._count_by_severity(threats)
        critical = sev_counts.get("critical", 0)
        high = sev_counts.get("high", 0)

        if risk_score >= 80 or severity == "critical" or critical:
            return (
                "Potential for data breach, service outage, or full account compromise. "
                "Business-critical systems may be exposed; escalate to incident response immediately."
            )
        if risk_score >= 60 or severity == "high" or high:
            return (
                "Elevated chance of unauthorized access and data exposure. "
                "Customer trust and compliance posture could be affected if uncontained."
            )
        if risk_score >= 40 or severity == "medium":
            return (
                "Moderate operational risk. Attackers may be probing defenses; "
                "unaddressed weaknesses can escalate into a material incident."
            )
        return (
            "Limited immediate business impact. Residual risk remains if monitoring gaps persist."
        )

    def _recommended_actions(self, analysis_data: dict, threats: list[dict]) -> list[str]:
        """Prioritized actions (P1 → P3 style)."""
        actions: list[str] = []

        # P1 — containment
        ips = self._top_ips(analysis_data, threats, limit=5)
        if ips:
            actions.append(f"P1 Containment: Block top attacker IPs ({', '.join(ips)}) at firewall/WAF.")
        if analysis_data.get("malware", {}).get("event_count", 0):
            actions.append("P1 Containment: Isolate affected hosts and preserve volatile evidence.")
        if analysis_data.get("critical_events", {}).get("event_count", 0):
            actions.append("P1 Escalation: Engage SOC/IR for privilege-escalation or critical system events.")

        # P2 — hardening
        if analysis_data.get("brute_force", {}).get("flagged_ips"):
            actions.append("P2 Hardening: Enforce MFA, account lockout, and fail2ban on authentication services.")
        if analysis_data.get("intrusion", {}).get("event_count", 0):
            actions.append("P2 Hardening: Deploy/update WAF rules; fix injection and path-traversal flaws.")
        if analysis_data.get("port_scan", {}).get("event_count", 0):
            actions.append("P2 Hardening: Reduce public attack surface; close unused ports.")

        # P3 — monitoring / recovery
        actions.append("P3 Monitoring: Increase log retention and alert on repeat offenders.")
        actions.append("P3 Recovery: Rotate credentials for targeted accounts and verify backup integrity.")

        # Deduplicate while preserving order
        seen: set[str] = set()
        prioritized: list[str] = []
        for a in actions:
            if a not in seen:
                seen.add(a)
                prioritized.append(a)
        return prioritized[:8]

    def _mitre_techniques(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, techniques in MITRE_BY_CATEGORY.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(techniques)
        return sorted(mapped) or ["T1078 - Valid Accounts (monitor)"]

    def _owasp_mapping(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            explicit = t.get("owasp")
            if explicit:
                mapped.add(str(explicit))
                continue
            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, entries in OWASP_BY_CATEGORY.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(entries)
        return sorted(mapped) or ["A05:2021 - Security Misconfiguration (baseline)"]

    def _incident_priority(self, risk_score: int, severity: str, threats: list[dict]) -> str:
        sev = self._count_by_severity(threats)
        if risk_score >= 80 or severity == "critical" or sev.get("critical", 0) > 0:
            return "P1 - Critical"
        if risk_score >= 60 or severity == "high" or sev.get("high", 0) >= 3:
            return "P2 - High"
        if risk_score >= 40 or severity == "medium":
            return "P3 - Medium"
        return "P4 - Low"

    def _next_investigation_steps(
        self,
        analysis_data: dict,
        threats: list[dict],
        priority: str,
    ) -> list[str]:
        steps = [
            "Correlate timestamps across auth, web, and system logs for the same source IPs.",
            "Validate whether any failed-login campaigns resulted in successful authentication.",
        ]
        ips = self._top_ips(analysis_data, threats, limit=3)
        if ips:
            steps.append(f"Pivot threat-intel lookups on: {', '.join(ips)}.")
        if analysis_data.get("intrusion", {}).get("event_count", 0):
            steps.append("Inspect application access logs for successful exploit payloads after failed attempts.")
        if analysis_data.get("malware", {}).get("event_count", 0):
            steps.append("Scan hosts for webshells, miners, and persistence (cron, services, startup).")
        if priority.startswith("P1") or priority.startswith("P2"):
            steps.append("Open a formal incident ticket and notify stakeholders within SLA.")
        else:
            steps.append("Document findings and schedule a follow-up review within 7 days.")
        return steps[:7]