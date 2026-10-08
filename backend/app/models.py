"""Database models.

Two databases:
  - identity (default bind): users, voters, candidates
  - ballots (bind "ballots"): ballot tokens and encrypted ballots

Nothing in the ballots database stores a voter id, a timestamp or an IP
address. That is the core of SR-14.
"""
from .extensions import db
from .security.pii import EncryptedText


# ---------- identity database ----------

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # voter | enrolment_officer | delegate | tally_officer | auditor
    role = db.Column(db.String(32), nullable=False)


class UserSession(db.Model):
    """SR-06: server-side record of a login session."""
    __tablename__ = "user_sessions"
    sid_hash = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    auth_at = db.Column(db.DateTime, nullable=False)  # last time the password was entered
    revoked = db.Column(db.Boolean, nullable=False, default=False)


class Voter(db.Model):
    __tablename__ = "voters"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    # SR-05: personal details encrypted at rest
    full_name = db.Column(EncryptedText("voters.full_name"), nullable=False)
    date_of_birth = db.Column(EncryptedText("voters.date_of_birth"))
    address = db.Column(EncryptedText("voters.address"))
    division = db.Column(db.String(64), nullable=False)
    enrolled = db.Column(db.Boolean, nullable=False, default=False)
    # Only a flag, no time. A "voted at" timestamp could be lined up with the
    # order of ballots in the ballot store to re-identify voters.
    ballot_issued = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User")


class Candidate(db.Model):
    __tablename__ = "candidates"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    party = db.Column(db.String(128))
    division = db.Column(db.String(64), nullable=False)
    ballot_order = db.Column(db.Integer, nullable=False)


# ---------- ballot database ----------

class BallotToken(db.Model):
    """One-time anonymous token. Only its SHA-256 hash is stored."""
    __bind_key__ = "ballots"
    __tablename__ = "ballot_tokens"
    token_hash = db.Column(db.String(64), primary_key=True)
    division = db.Column(db.String(64), nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)


class ChainHead(db.Model):
    """Single row holding the latest position of the ballot hash chain.
    Locked while a ballot is appended so the chain stays linear."""
    __bind_key__ = "ballots"
    __tablename__ = "chain_head"
    id = db.Column(db.Integer, primary_key=True)
    last_seq = db.Column(db.Integer, nullable=False, default=0)
    last_mac = db.Column(db.String(64), nullable=False)


class CastBallot(db.Model):
    __bind_key__ = "ballots"
    __tablename__ = "cast_ballots"
    seq = db.Column(db.Integer, primary_key=True, autoincrement=False)
    ballot_id = db.Column(db.String(36), unique=True, nullable=False)
    election_id = db.Column(db.String(64), nullable=False)
    division = db.Column(db.String(64), nullable=False)
    # SR-13: only ciphertext is stored
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    wrapped_key = db.Column(db.LargeBinary, nullable=False)
    # SR-15: per-ballot digest + keyed hash chain
    digest = db.Column(db.String(64), nullable=False)
    chain_mac = db.Column(db.String(64), nullable=False)


class IntegrityAlert(db.Model):
    __bind_key__ = "ballots"
    __tablename__ = "integrity_alerts"
    id = db.Column(db.Integer, primary_key=True)
    seq = db.Column(db.Integer)
    reason = db.Column(db.String(255), nullable=False)
