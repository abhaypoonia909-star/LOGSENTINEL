"""
CyberShield AI – Code Vulnerability Scanner orchestrator.
Routes files to language-specific scanners, handles ZIP projects, scores risk.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from services.html_scanner import HTMLScanner
from services.js_scanner import JavaScriptScanner
from services.php_scanner import PHPScanner
from services.python_scanner import PythonScanner

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
}

SCANNABLE_EXTENSIONS = {".py", ".js", ".php", ".html", ".css"}


@dataclass
class VulnerabilityFinding:
    line: int
    severity: str
    type: str
    description: str
    recommendation: str
    owasp: str
    cwe: str
    file: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CodeScannerService:
    def __init__(self) -> None:
        self._scanners = {
            ".py": PythonScanner(),
            ".js": JavaScriptScanner(),
            ".php": PHPScanner(),
            ".html": HTMLScanner(),
            ".css": HTMLScanner(),  # inline style / script patterns
        }

    def scan_file(self, content: str, filename: str) -> dict:
        ext = Path(filename).suffix.lower()
        findings = self._scan_content(content, filename, ext)
        return self._build_result(filename, findings)

    def scan_zip(self, raw: bytes, zip_name: str) -> dict:
        findings: list[VulnerabilityFinding] = []
        scanned_files: list[str] = []

        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    inner_name = Path(info.filename).name
                    ext = Path(inner_name).suffix.lower()
                    if ext not in SCANNABLE_EXTENSIONS:
                        continue
                    if info.file_size > 512_000:  # skip very large files
                        continue
                    try:
                        content = archive.read(info).decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    scanned_files.append(info.filename)
                    findings.extend(self._scan_content(content, info.filename, ext))
        except zipfile.BadZipFile as exc:
            raise ValueError("Invalid or corrupted ZIP archive.") from exc

        if not scanned_files:
            raise ValueError("ZIP contains no scannable source files (.py, .js, .php, .html, .css).")

        return self._build_result(zip_name, findings, scanned_files=scanned_files)

    def _scan_content(self, content: str, filename: str, ext: str) -> list[VulnerabilityFinding]:
        scanner = self._scanners.get(ext)
        if not scanner:
            return []
        return scanner.scan(content, filename)

    def _build_result(
        self,
        filename: str,
        findings: list[VulnerabilityFinding],
        scanned_files: list[str] | None = None,
    ) -> dict:
        risk_score = self._calculate_score(findings)
        severity = self._overall_severity(risk_score)
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            breakdown[f.severity] = breakdown.get(f.severity, 0) + 1

        return {
            "filename": filename,
            "risk_score": risk_score,
            "severity": severity,
            "vulnerability_count": len(findings),
            "severity_breakdown": breakdown,
            "scanned_files": scanned_files or [filename],
            "vulnerabilities": [f.to_dict() for f in findings],
        }

    def _calculate_score(self, findings: list[VulnerabilityFinding]) -> int:
        total = sum(SEVERITY_WEIGHTS.get(f.severity, 2) for f in findings)
        return min(total, 100)

    def _overall_severity(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"