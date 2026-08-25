from functools import wraps
from datetime import datetime, timedelta
import jwt
from flask import request, jsonify, g
from config import Config

def create_token(user_id: int, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

def _extract_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None

def decode_token(token: str) -> dict:
    return jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])

def optional_jwt(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        g.current_user = None
        token = _extract_token()
        if token:
            try:
                payload = decode_token(token)
                g.current_user = {
                    "id": payload["sub"],
                    "email": payload["email"],
                    "role": payload["role"],
                }
            except jwt.PyJWTError:
                pass
        return view(*args, **kwargs)
    return wrapper

def require_jwt(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authorization token required."}), 401
        try:
            payload = decode_token(token)
            g.current_user = {
                "id": payload["sub"],
                "email": payload["email"],
                "role": payload["role"],
            }
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired."}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid token."}), 401
        return view(*args, **kwargs)
    return wrapper

def owns_or_admin(owner_id) -> bool:
    """True when the current user owns the record, or is an admin.

    Records created before authentication existed have owner_id = None; those
    stay visible to admins only.
    """
    current = getattr(g, "current_user", None)
    if not current:
        return False
    if current.get("role") == "admin":
        return True
    return owner_id is not None and owner_id == current.get("id")


def require_admin(view):
    @wraps(view)
    @require_jwt
    def wrapper(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return view(*args, **kwargs)
    return wrapper
