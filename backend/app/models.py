"""Database models.

Three databases:
  - identity (default bind): users, voters, candidates
  - ballots (bind "ballots"): ballot tokens and encrypted ballots
  - audit (bind "audit"): append-only audit log

Nothing in the ballots database stores a voter id, a timestamp or an IP
address. That is the core of SR-14.
"""
from sqlalchemy import DDL, event

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
    state = db.Column(db.String(3))  # delegates only: the state they act for (SR-17)
    # SR-03 lockout
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    # SR-01 MFA: TOTP secret encrypted with the MFA key, never stored in plain
    mfa_secret_enc = db.Column(db.LargeBinary)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_last_step = db.Column(db.Integer)  # last accepted 30 s step, blocks code replay


class UserSession(db.Model):
    """SR-06: server-side record of a login session."""
    __tablename__ = "user_sessions"
    sid_hash = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    auth_at = db.Column(db.DateTime, nullable=False)  # last time the password was entered
    revoked = db.Column(db.Boolean, nullable=False, default=False)


class ExportRequest(db.Model):
    """SR-07: a request to export elector records."""
    __tablename__ = "export_requests"
    id = db.Column(db.Integer, primary_key=True)
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    division = db.Column(db.String(64))  # None = whole roll
    record_count = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    requested_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(16), nullable=False)  # pending|approved|rejected|expired|downloaded
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    decided_at = db.Column(db.DateTime)
    downloaded_at = db.Column(db.DateTime)


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
    state = db.Column(db.String(3), nullable=False, default="VIC")
    ballot_order = db.Column(db.Integer, nullable=False)
    # SR-17: set only through an approved exclusion (court-ordered recount)
    excluded = db.Column(db.Boolean, nullable=False, default=False)
    exclusion_reason = db.Column(db.String(500))


class PendingChange(db.Model):
    """SR-17: a candidate change waiting for a second delegate."""
    __tablename__ = "pending_changes"
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(16), nullable=False)  # create | update | exclude
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"))
    state = db.Column(db.String(3), nullable=False)
    payload = db.Column(db.Text, nullable=False)  # JSON of the requested values
    reason = db.Column(db.String(500), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    requested_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending")  # pending|applied|rejected|withdrawn|expired
    decided_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    decided_at = db.Column(db.DateTime)


class ResultsPackage(db.Model):
    """SR-18: a signed, published results package. Aggregates only."""
    __tablename__ = "results_packages"
    seq = db.Column(db.Integer, primary_key=True)
    payload = db.Column(db.Text, nullable=False)  # canonical JSON that was signed
    kid = db.Column(db.String(16), nullable=False)
    signature = db.Column(db.String(128), nullable=False)


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


# ---------- audit database (SR-04) ----------

class AuditEvent(db.Model):
    __bind_key__ = "audit"
    __tablename__ = "audit_events"
    seq = db.Column(db.Integer, primary_key=True, autoincrement=False)
    occurred_at = db.Column(db.String(32), nullable=False)  # ISO 8601 UTC, or date only
    actor_id = db.Column(db.Integer)
    event = db.Column(db.String(64), nullable=False)
    source_ip = db.Column(db.String(64))
    details = db.Column(db.Text, nullable=False)  # canonical JSON, incl. before/after values
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)


class AuditHead(db.Model):
    __bind_key__ = "audit"
    __tablename__ = "audit_head"
    id = db.Column(db.Integer, primary_key=True)
    last_seq = db.Column(db.Integer, nullable=False, default=0)
    last_hash = db.Column(db.String(64), nullable=False)


# The database itself refuses UPDATE and DELETE on audit rows, so even code
# with a bug (or someone with normal DB access) can only append.
for op in ("UPDATE", "DELETE"):
    event.listen(AuditEvent.__table__, "after_create", DDL(
        f"CREATE TRIGGER audit_no_{op.lower()} BEFORE {op} ON audit_events "
        f"BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END"
    ).execute_if(dialect="sqlite"))

event.listen(AuditEvent.__table__, "after_create", DDL("""
CREATE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_append_only();
""").execute_if(dialect="postgresql"))
