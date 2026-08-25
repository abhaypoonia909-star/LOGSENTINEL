from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models import db
from models.models import User, UploadedFile, Analysis, Threat, Report, ensure_user_schema
from routes.auth import auth_bp
from routes.upload import upload_bp
from routes.analysis import analysis_bp
from routes.dashboard import dashboard_bp
from routes.reports import reports_bp
from routes.charts import charts_bp
from routes.ai import ai_bp
from routes.code_analysis import code_analysis_bp
from threat_intelligence.routes import threat_intel_bp


limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)
    limiter.init_app(app)
    limiter.default_limits = [Config.RATE_LIMIT]

    db.init_app(app)
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        db.create_all()
        ensure_user_schema()

    app.register_blueprint(auth_bp, url_prefix="/api")
    # Tighter rate limit on the credential endpoints (brute-force defence).
    limiter.limit(Config.AUTH_RATE_LIMIT)(auth_bp)
    app.register_blueprint(upload_bp, url_prefix="/api")
    app.register_blueprint(analysis_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")
    app.register_blueprint(charts_bp, url_prefix="/api")
    app.register_blueprint(ai_bp, url_prefix="/api")
    app.register_blueprint(code_analysis_bp, url_prefix="/api")
    app.register_blueprint(threat_intel_bp)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "LogSentinel"})

    @app.get("/api")
    def api_index():
        return jsonify({
            "service": "LogSentinel API",
            "base_url": "/api",
            "endpoints": [
                "POST /api/register",
                "POST /api/login",
                "GET  /api/me",
                "POST /api/logout",
                "POST /api/upload",
                "POST /api/analyze",
                "GET  /api/dashboard",
                "GET  /api/report/<analysis_id>",
                "GET  /api/charts/<analysis_id>",
                "POST /api/ai",
                "POST /api/code-scan",
                "GET  /api/code-report/<analysis_id>",
                "GET  /api/health",
            ],
        })

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
