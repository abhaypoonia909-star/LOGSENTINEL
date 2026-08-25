from flask import Blueprint, request, jsonify
from services.ai_service import AIService
from utils.validators import sanitize_text
from utils.jwt_utils import require_jwt

ai_bp = Blueprint("ai", __name__)
ai = AIService()

@ai_bp.post("/ai")
@require_jwt
def ai_assistant():
    data = request.get_json(silent=True) or {}
    question = sanitize_text(data.get("question", ""), 2000)
    analysis_data = data.get("analysis_data")

    if not question:
        return jsonify({"error": "Field 'question' is required."}), 400

    answer = ai.answer(question, analysis_data)
    return jsonify({
        "question": question,
        "explanation": answer["explanation"],
        "risk": answer["risk"],
        "prevention": answer["prevention"],
    })