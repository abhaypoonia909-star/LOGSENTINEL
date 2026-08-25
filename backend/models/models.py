from datetime import datetime
from models import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # admin | user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("UploadedFile", backref="user", lazy=True)
    analyses = db.relationship("Analysis", backref="user", lazy=True)


class UploadedFile(db.Model):
    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    file_format = db.Column(db.String(50), default="unknown")
    size_bytes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    analysis = db.relationship("Analysis", backref="file", uselist=False)


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey("uploaded_files.id"), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    severity = db.Column(db.String(20), default="low")
    total_lines = db.Column(db.Integer, default=0)
    threat_count = db.Column(db.Integer, default=0)
    result_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    threats = db.relationship("Threat", backref="analysis", lazy=True, cascade="all, delete-orphan")
    report = db.relationship("Report", backref="analysis", uselist=False, cascade="all, delete-orphan")


class Threat(db.Model):
    __tablename__ = "threats"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(64))
    message = db.Column(db.Text)
    path = db.Column(db.Text)
    timestamp = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def ensure_user_schema():
    """Add the `username` column to an existing `users` table if it is missing.

    `db.create_all()` only creates tables that do not exist yet - it will not
    alter a table that was created before `username` was introduced. This keeps
    already-deployed databases (SQLite locally, Postgres on Railway) working
    without pulling in a migration framework.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("users")}
    if "username" in columns:
        return
    with db.engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(80)"))
    print("[LogSentinel] Added missing 'users.username' column.", flush=True)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False, unique=True)
    summary = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    json_path = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)