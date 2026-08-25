import json
from flask import Blueprint, jsonify
from models.models import Analysis, Report
from utils.jwt_utils import require_jwt, owns_or_admin

reports_bp = Blueprint("reports", __name__)

@reports_bp.get("/report/<int:analysis_id>")
@require_jwt
def get_report(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403

    data = json.loads(analysis.result_json)
    report = Report.query.filter_by(analysis_id=analysis_id).first()

    return jsonify({
        "analysis_id": analysis.id,
        "summary": json.loads(report.summary) if report else {},
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "threat_details": data.get("threats", []),
        "recommendations": json.loads(report.recommendations) if report else [],
        "analysis": data,
    })