"""POST /api/code-scan – source code and ZIP vulnerability scanning."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request, g

from config import Config
from models import db
from models.models import Analysis, Report, Threat, UploadedFile
from services.code_scanner import CodeScannerService
from services.report_service import ReportService
from utils.jwt_utils import require_jwt, owns_or_admin
from utils.security import save_upload

code_analysis_bp = Blueprint("code_analysis", __name__)
scanner = CodeScannerService()

ALLOWED = {".py", ".js", ".php", ".html", ".css", ".zip"}


def _persist_code_scan(filename: str, stored_name: str, result: dict) -> int:
    user_id = g.current_user["id"] if getattr(g, "current_user", None) else None

    file_row = UploadedFile(
        user_id=user_id,
        original_name=filename,
        stored_name=stored_name,
        file_format="code",
        size_bytes=0,
    )
    db.session.add(file_row)
    db.session.flush()

    analysis_row = Analysis(
        user_id=user_id,
        file_id=file_row.id,
        risk_score=result["risk_score"],
        severity=result["severity"].lower(),
        total_lines=sum(1 for _ in open(Config.UPLOAD_DIR / stored_name, errors="ignore")) if (Config.UPLOAD_DIR / stored_name).exists() else 0,
        threat_count=result["vulnerability_count"],
        result_json=json.dumps(result),
    )
    db.session.add(analysis_row)
    db.session.flush()

    for vuln in result["vulnerabilities"]:
        db.session.add(Threat(
            analysis_id=analysis_row.id,
            category=vuln["type"],
            severity=vuln["severity"].lower(),
            message=vuln["description"],
            path=f"{vuln['file']}:{vuln['line']}",
        ))

    report_payload = {
        "analysis_id": analysis_row.id,
        "summary": {
            "filename": filename,
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "vulnerability_count": result["vulnerability_count"],
        },
        "risk_score": result["risk_score"],
        "threat_details": result["vulnerabilities"],
        "recommendations": list({v["recommendation"] for v in result["vulnerabilities"]}) or [
            "No vulnerabilities detected. Continue secure coding practices."
        ],
    }
    report_path = Config.REPORT_DIR / f"code_report_{analysis_row.id}.json"
    Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    db.session.add(Report(
        analysis_id=analysis_row.id,
        summary=json.dumps(report_payload["summary"]),
        recommendations=json.dumps(report_payload["recommendations"]),
        json_path=str(report_path),
    ))
    db.session.commit()
    return analysis_row.id


@code_analysis_bp.post("/code-scan")
@require_jwt
def code_scan():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "No file uploaded. Use form field 'file'."}), 400

    ext = Path(upload.filename).suffix.lower()
    if ext not in ALLOWED:
        return jsonify({"error": f"Unsupported file type '{ext}'. Allowed: {sorted(ALLOWED)}"}), 400

    raw = upload.read()
    if not raw:
        return jsonify({"error": "Uploaded file is empty."}), 400

    if len(raw) > Config.MAX_CONTENT_LENGTH:
        return jsonify({"error": "File exceeds maximum upload size."}), 413

    try:
        stored_name, _ = save_upload(upload.filename, raw)

        if ext == ".zip":
            result = scanner.scan_zip(raw, upload.filename)
        else:
            content = raw.decode("utf-8", errors="replace")
            result = scanner.scan_file(content, upload.filename)

        analysis_id = _persist_code_scan(upload.filename, stored_name, result)

        return jsonify({
            "analysis_id": analysis_id,
            "scan_type": "code",
            "scanned_at": datetime.utcnow().isoformat(),
            "report_url": f"/api/code-report/{analysis_id}",
            **result,
        })

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Code scan failed: {exc}"}), 500


@code_analysis_bp.get("/code-report/<int:analysis_id>")
@require_jwt
def code_report(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403
    return jsonify(json.loads(analysis.result_json))