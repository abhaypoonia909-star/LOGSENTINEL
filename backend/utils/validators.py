import re
from pathlib import Path
from config import Config

# --- Authentication validators (added) -----------------------------------
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")


def validate_email(email: str) -> bool:
    return bool(email) and len(email) <= 255 and bool(_EMAIL_RE.match(email))


def validate_username(username: str) -> bool:
    return bool(username) and bool(_USERNAME_RE.match(username))


def validate_password(password: str) -> tuple[bool, str]:
    """Return (ok, message). Message is safe to show to the user."""
    min_len = Config.PASSWORD_MIN_LENGTH
    if not password or len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long."
    if len(password) > 128:
        return False, "Password must be 128 characters or fewer."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, ""


def validate_log_extension(filename: str) -> bool:
    return Path(filename).suffix.lower() in Config.ALLOWED_LOG_EXT

def sanitize_text(value: str, max_len: int = 5000) -> str:
    return (value or "").strip()[:max_len]