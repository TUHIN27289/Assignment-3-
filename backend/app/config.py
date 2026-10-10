import os
import secrets
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # Identity data (users, voters, candidates) and ballots live in two
    # separate databases so no single query can join a voter to a ballot (SR-14).
    SQLALCHEMY_DATABASE_URI = os.environ.get("IDENTITY_DB_URL", "sqlite:///identity.db")
    SQLALCHEMY_BINDS = {
        "ballots": os.environ.get("BALLOT_DB_URL", "sqlite:///ballots.db"),
        # Audit log in its own database so it can have its own access rules (SR-04)
        "audit": os.environ.get("AUDIT_DB_URL", "sqlite:///audit.db"),
    }

    # Key material is kept outside the source tree (SR-20).
    KEY_DIR = os.environ.get("KEY_DIR", os.path.join(os.getcwd(), "instance", "keys"))
    # SR-20: set in production so private keys are encrypted on disk
    KEY_PASSPHRASE = os.environ.get("KEY_PASSPHRASE")

    ELECTION_ID = os.environ.get("ELECTION_ID", "federal-2026")
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "https://localhost:5173")

    # Session cookie hardening (SR-16)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    FORCE_HTTPS = True
    RATELIMIT_STORAGE_URI = "memory://"


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_BINDS = {"ballots": "sqlite://", "audit": "sqlite://"}
    FORCE_HTTPS = False
