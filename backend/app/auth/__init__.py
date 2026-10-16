"""Authentication and access checks.

SR-02: permission_required() checks the logged-in user's role against the
permission table in security/rbac.py. The role is read from the database on
every request, never trusted from the client or cached in the session.
SR-03: login protection
  - Argon2id password hashing with explicit parameters, rehash on login if
    the parameters are ever raised
  - account locked for 15 minutes after 5 wrong passwords
  - 10 login attempts per minute per IP (Flask-Limiter)
  - unknown emails still run a full Argon2 check, so response time doesn't
    reveal which emails have accounts
  - the same 401 for unknown user, wrong password and locked account
  - every attempt goes to the audit log (SR-04)
SR-01: staff accounts need a TOTP code after the password (see mfa.py).
SR-06 (session management) extends this.
"""
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Blueprint, abort, g, jsonify, request, session

from .. import audit
from ..extensions import db, limiter
from ..models import User
from ..security.http import get_csrf_token
from ..security.rbac import has_permission, public
from . import sessions  # noqa: E402  (SR-06)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
# Argon2id, parameters as recommended by RFC 9106 (low-memory option)
ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)
_DUMMY_HASH = ph.hash("timing-equaliser-not-a-real-password")

MAX_FAILED_LOGINS = 5
MFA_ROLES = {"enrolment_officer", "delegate", "tally_officer", "auditor"}
LOCKOUT = timedelta(minutes=15)
MIN_PASSWORD_LENGTH = 12
COMMON_PASSWORDS = {"password1234", "123456789012", "qwertyuiop12", "letmein12345", "australia123"}


def hash_password(password):
    return ph.hash(password)


def check_password_policy(password, email=""):
    """Returns a list of problems, empty if the password is acceptable.
    Use wherever an account is created or a password changed."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("is too common")
    local = email.split("@")[0].lower()
    if local and len(local) >= 4 and local in password.lower():
        problems.append("must not contain your email name")
    return problems


def _verify(stored_hash, password):
    try:
        return ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def current_user():
    return sessions.current_session_user()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        g.user = current_user()
        if g.user is None:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


def permission_required(permission):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if not has_permission(g.user.role, permission):
                audit.record("access_denied", g.user.id, path=request.path, needed=permission)
                abort(403)
            return view(*args, **kwargs)
        wrapper._permission = permission
        return wrapper
    return decorator


@bp.post("/login")
@public
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).lower()
    password = str(data.get("password", ""))
    user = User.query.filter_by(email=email).first()

    if user is None:
        _verify(_DUMMY_HASH, password)  # same amount of work as a real check
        audit.record("login_failed", None, email=email[:254], reason="unknown user")
        abort(401)

    if user.locked_until and user.locked_until > _now():
        _verify(user.password_hash, password)  # same work as a wrong password, so timing does not reveal the lock
        audit.record("login_failed", user.id, reason="account locked")
        abort(401)

    if not _verify(user.password_hash, password):
        register_failed_attempt(user, "wrong password")
        abort(401)

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)

    if user.role in MFA_ROLES:
        # Don't reset the failed-attempt counter yet: only a correct MFA code does
        # that (mfa_verify). Otherwise a stolen password could be re-entered to
        # reset the counter between batches of MFA guesses.
        db.session.commit()
        # Password was right, but no access until the second factor is checked.
        session.clear()
        session["mfa_uid"] = user.id
        session["mfa_started"] = int(time.time())
        audit.record("login_password_ok", user.id)
        step = "mfa_required" if user.mfa_enabled else "mfa_setup_required"
        return jsonify({step: True, "csrf_token": get_csrf_token()})

    user.failed_logins = 0
    user.locked_until = None
    db.session.commit()
    start_session(user)
    audit.record("login_ok", user.id, coarse_time=(user.role == "voter"))
    return jsonify(role=user.role, csrf_token=get_csrf_token())


def start_session(user):
    """SR-06: create the server-side session (see sessions.py). Kept under this
    name so the MFA login in mfa.py gets it too."""
    sessions.start(user)


def register_failed_attempt(user, reason):
    """Shared by password and MFA checks, so both count towards the lockout."""
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED_LOGINS:
        user.locked_until = _now() + LOCKOUT
        user.failed_logins = 0
        reason += ", account locked"
    db.session.commit()
    audit.record("login_failed", user.id, reason=reason)


@bp.post("/logout")
@public
def logout():
    sessions.end()
    return jsonify(ok=True)


@bp.post("/logout-all")
@permission_required("self:read")
def logout_all():
    n = sessions.revoke_all(g.user.id)
    session.clear()
    audit.record("sessions_revoked_all", g.user.id, sessions=n)
    return jsonify(ok=True, ended=n)


@bp.post("/reauth")
@permission_required("self:read")
@limiter.limit("5 per minute")
def reauth():
    """SR-06: confirm the password again before a sensitive change.

    Wrong passwords here count towards the same lockout as the login page
    (SR-03), so a hijacked session cannot be used to guess the password."""
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    user = g.user
    if user.locked_until and user.locked_until > _now():
        _verify(user.password_hash, password)  # same work as a real check
        audit.record("reauth_failed", user.id, reason="account locked")
        abort(401, description="password incorrect")
    if not _verify(user.password_hash, password):
        register_failed_attempt(user, "wrong password on re-authentication")
        if user.locked_until and user.locked_until > _now():
            sessions.revoke_all(user.id)  # locked out: end every session
            session.clear()
        abort(401, description="password incorrect")
    sessions.confirm_password_now()
    audit.record("reauth_ok", user.id)
    return jsonify(ok=True)


@bp.get("/me")
@permission_required("self:read")
def me():
    return jsonify(id=g.user.id, email=g.user.email, role=g.user.role)


from . import mfa  # noqa: E402,F401  registers the /api/auth/mfa routes
