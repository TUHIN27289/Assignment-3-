import os
import secrets
from datetime import timedelta

DEV_ENVIRONMENTS = ("development", "test")


def is_production(app_env):
    """Fail safe: anything that isn't explicitly development or test is treated
    as production, including a missing or mistyped APP_ENV."""
    return app_env not in DEV_ENVIRONMENTS


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
    # SR-20: encrypts private keys and secrets on disk. Required in production.
    KEY_PASSPHRASE = os.environ.get("KEY_PASSPHRASE")
    # Production unless told otherwise, so a forgotten setting fails safe.
    # run.py and seed.py set development for local use.
    APP_ENV = os.environ.get("APP_ENV", "production")

    ELECTION_ID = os.environ.get("ELECTION_ID", "federal-2026")
    # SR-18: results can't be signed or published before polls close.
    # ISO 8601, e.g. 2026-10-24T18:00:00+11:00. Required in production.
    ELECTION_CLOSES_AT = os.environ.get("ELECTION_CLOSES_AT")
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
    APP_ENV = "test"
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_BINDS = {"ballots": "sqlite://", "audit": "sqlite://"}
    FORCE_HTTPS = False
