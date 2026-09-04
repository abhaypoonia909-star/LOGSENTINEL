import json
from collections import Counter
from pathlib import Path
from typing import Any

from config import Config


class ReportService:
    """
    Enterprise Security Report Generator.

    Backward compatibility:
    - Preserves existing `build()` return signature: (report_dict, report_path)
    - Preserves existing keys used by API/front-end:
      analysis_id, summary, risk_score, threat_details, recommendations, analysis
    - Adds new report fields without removing old ones.
    """

    # MITRE ATT&CK mapping by threat category/pattern
    _MITRE_MAP = {
        "Brute Force": ["T1110 - Brute Force"],
        "Port Scan": ["T1046 - Network Service Discovery"],
        "Intrusion": ["T1190 - Exploit Public-Facing Application"],
        "Critical Event": ["T1068 - Exploitation for Privilege Escalation"],
        "Malware Indicator": ["T1105 - Ingress Tool Transfer", "T1059 - Command and Scripting Interpreter"],
        "SQL Injection": ["T1190 - Exploit Public-Facing Application"],
        "Cross-Site Scripting (XSS)": ["T1059.007 - JavaScript"],
        "Directory Traversal": ["T1005 - Data from Local System"],
        "Command Injection": ["T1059 - Command and Scripting Interpreter"],
        "Reverse Shell": ["T1059 - Command and Scripting Interpreter", "T1071 - Application Layer Protocol"],
        "Suspicious PowerShell": ["T1059.001 - PowerShell"],
        "Web Shell": ["T1505.003 - Web Shell"],
        "Privilege Escalation / Unauthorized Access": ["T1068 - Exploitation for Privilege Escalation"],
    }

    # OWASP Top 10 mapping by threat category/pattern
    _OWASP_MAP = {
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
        "Web Shell": ["A03:2021 - Injection", "A08:2021 - Software and Data Integrity Failures"],
        "Privilege Escalation / Unauthorized Access": ["A01:2021 - Broken Access Control"],
    }

    def build(self, analysis_record, analysis_data: dict) -> tuple[dict[str, Any], str]:
        """
        Build full JSON report and persist it to reports/report_<analysis_id>.json.
        """
        threats = analysis_data.get("threats", []) or []
        confidence = self._derive_confidence(analysis_record, analysis_data)

        # Keep old recommendations logic and extend it with targeted advice.
        recommendations = self._build_recommendations(analysis_data, threats)

        # Existing summary payload kept intact.
        summary = {
            "filename": analysis_record.file.original_name,
            "risk_score": analysis_record.risk_score,
            "severity": analysis_record.severity,
            "threat_count": analysis_record.threat_count,
            "total_lines": analysis_record.total_lines,
        }

        # New enterprise sections
        threat_summary = self._build_threat_summary(threats)
        top_attacker_ips = self._top_attacker_ips(threats, analysis_data)
        mitre_mapping = self._build_mitre_mapping(threats)
        owasp_mapping = self._build_owasp_mapping(threats)
        executive_summary = self._build_executive_summary(summary, threat_summary, confidence)
        security_conclusion = self._build_security_conclusion(summary, confidence, threat_summary)

        report = {
            # ---- Backward-compatible fields (existing API contract) ----
            "analysis_id": analysis_record.id,
            "summary": summary,
            "risk_score": analysis_record.risk_score,
            "threat_details": threats,
            "recommendations": recommendations,
            "analysis": analysis_data,

            # ---- New professional sections (additive only) ----
            "executive_summary": executive_summary,
            "severity": analysis_record.severity,
            "confidence_score": confidence,
            "threat_summary": threat_summary,
            "top_attacker_ips": top_attacker_ips,
            "mitre_attack_mapping": mitre_mapping,
            "owasp_top_10_mapping": owasp_mapping,
            "security_conclusion": security_conclusion,
        }

        Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        path = Config.REPORT_DIR / f"report_{analysis_record.id}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return report, str(path)

    def build_preview(self, analysis_data: dict, filename: str, fmt: str) -> str:
        """
        Backward-compatible text preview used by current UI flows.
        Kept as plain text to avoid breaking existing frontend behavior.
        """
        lines = [
            "=" * 60,
            "LOGSENTINEL ANALYSIS REPORT",
            "=" * 60,
            f"File: {filename}",
            f"Format: {fmt}",
            f"Risk Score: {analysis_data.get('risk_score', 0)}/100",
            f"Severity: {str(analysis_data.get('severity', 'low')).upper()}",
            f"Confidence: {analysis_data.get('confidence', 65)}%",
            f"Threats: {len(analysis_data.get('threats', []))}",
            "",
            "RECOMMENDATIONS",
            "-" * 60,
        ]

        # Preserve existing preview structure
        for t in analysis_data.get("threats", [])[:20]:
            lines.append(
                f"- [{str(t.get('severity', '')).upper()}] "
                f"{t.get('category')}: "
                f"{t.get('message', t.get('description', ''))}"
            )

        if len(lines) == 10:
            lines.append("- No immediate action required. Continue monitoring.")

        lines.extend([
            "",
            "=" * 60,
            "End of Report",
        ])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------

    def _derive_confidence(self, analysis_record, analysis_data: dict) -> int:
        """
        Prefer analyzer-provided confidence; otherwise compute from signal strength.
        """
        provided = analysis_data.get("confidence")
        if isinstance(provided, (int, float)):
            return max(0, min(100, int(provided)))

        threat_count = int(getattr(analysis_record, "threat_count", 0) or 0)
        total_lines = int(getattr(analysis_record, "total_lines", 0) or 0)
        risk_score = int(getattr(analysis_record, "risk_score", 0) or 0)

        # Conservative heuristic confidence.
        detector_density = min(1.0, threat_count / max(total_lines, 1) * 100)
        confidence = int(min(100, 45 + (risk_score * 0.35) + (detector_density * 20)))
        return max(30, confidence)

    def _build_recommendations(self, analysis_data: dict, threats: list[dict]) -> list[str]:
        recommendations: list[str] = []

        # Preserve existing logic
        if analysis_data.get("brute_force", {}).get("flagged_ips"):
            recommendations.append("Block flagged IPs and enable fail2ban.")

        if analysis_data.get("intrusion", {}).get("event_count", 0) > 0:
            recommendations.append("Review WAF rules and sanitize user inputs.")

        if analysis_data.get("port_scan", {}).get("event_count", 0) > 0:
            recommendations.append("Restrict exposed ports and monitor reconnaissance traffic.")

        # Add targeted recommendations from threats
        for t in threats:
            rec = t.get("recommendation")
            if rec and rec not in recommendations:
                recommendations.append(rec)

        if not recommendations:
            recommendations.append("No immediate action required. Continue monitoring.")

        return recommendations[:12]

    def _build_threat_summary(self, threats: list[dict]) -> dict[str, Any]:
        by_severity = Counter(str(t.get("severity", "low")).lower() for t in threats)
        by_category = Counter(str(t.get("category", "Unknown")) for t in threats)

        return {
            "total_threats": len(threats),
            "severity_breakdown": {
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "medium": by_severity.get("medium", 0),
                "low": by_severity.get("low", 0),
            },
            "category_breakdown": dict(by_category),
        }

    def _top_attacker_ips(self, threats: list[dict], analysis_data: dict) -> list[dict[str, Any]]:
        ip_counter = Counter()

        # Count from flattened threat list
        for t in threats:
            ip = t.get("source_ip")
            if ip:
                ip_counter[str(ip)] += 1

        # Include brute-force IP counts if present
        for ip_info in analysis_data.get("brute_force", {}).get("flagged_ips", []):
            ip = ip_info.get("ip_address")
            attempts = int(ip_info.get("attempt_count", 1))
            if ip:
                ip_counter[str(ip)] += attempts

        return [{"ip": ip, "events": count} for ip, count in ip_counter.most_common(10)]

    def _build_mitre_mapping(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, tactics in self._MITRE_MAP.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(tactics)
        return sorted(mapped)

    def _build_owasp_mapping(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            # Prefer explicit owasp tag from analyzer if present
            explicit = t.get("owasp")
            if explicit:
                mapped.add(str(explicit))
                continue

            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, entries in self._OWASP_MAP.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(entries)
        return sorted(mapped)

    def _build_executive_summary(
        self,
        summary: dict[str, Any],
        threat_summary: dict[str, Any],
        confidence: int,
    ) -> str:
        return (
            f"Log file '{summary.get('filename')}' was analyzed with risk score "
            f"{summary.get('risk_score', 0)}/100 ({str(summary.get('severity', 'low')).upper()}). "
            f"Detected {threat_summary.get('total_threats', 0)} security events. "
            f"Assessment confidence is {confidence}%."
        )

    def _build_security_conclusion(
        self,
        summary: dict[str, Any],
        confidence: int,
        threat_summary: dict[str, Any],
    ) -> str:
        score = int(summary.get("risk_score", 0))
        sev = str(summary.get("severity", "low")).lower()
        critical_count = threat_summary.get("severity_breakdown", {}).get("critical", 0)

        if score >= 80 or sev == "critical" or critical_count > 0:
            return (
                "Critical security posture. Immediate incident response is recommended, "
                "including containment, threat hunting, and forensic evidence preservation."
            )
        if score >= 60 or sev == "high":
            return (
                "High risk posture. Prioritize remediation of identified attack paths and "
                "increase monitoring for lateral movement and persistence."
            )
        if score >= 40 or sev == "medium":
            return (
                "Moderate risk posture. Address exposed weaknesses and harden controls to "
                "prevent escalation."
            )
        return (
            "Low risk posture. No active critical threats observed, but continue continuous "
            "monitoring and periodic security validation."
        )