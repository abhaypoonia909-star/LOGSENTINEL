import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    JWT_SECRET = os.environ.get("JWT_SECRET", SECRET_KEY)
    JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", 24))

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'logsentinel.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_DIR = BASE_DIR / "uploads"
    REPORT_DIR = BASE_DIR / "reports"
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", 10)) * 1024 * 1024
    RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")

    ALLOWED_LOG_EXT = {".log", ".txt", ".json"}
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5))

    # --- Authentication settings (added) ---------------------------------
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 8))
    AUTH_RATE_LIMIT = os.environ.get("AUTH_RATE_LIMIT", "10/minute")
    # Comma-separated list of emails that receive the "admin" role at signup.
    ADMIN_EMAILS = {
        e.strip().lower()
        for e in os.environ.get("ADMIN_EMAILS", "").split(",")
        if e.strip()
    }


# Loud startup warning instead of silently shipping the placeholder secret.
if not os.environ.get("SECRET_KEY") and not os.environ.get("JWT_SECRET"):
    print(
        "[LogSentinel][WARNING] SECRET_KEY / JWT_SECRET is not set - falling back to "
        "the development placeholder. Set SECRET_KEY in your Railway variables "
        "before serving real users, or every issued JWT is forgeable.",
        flush=True,
    )