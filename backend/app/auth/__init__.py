"""Authentication (base version).

Enough to log in and check roles so the other modules can be built.
SR-01 (MFA), SR-02 (full RBAC), SR-03 (lockout/rate limiting) and SR-06
(session management) extend this.
"""
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from flask import Blueprint, abort, g, jsonify, request, session

from .. import audit
from ..extensions import db, limiter
from ..models import User
from ..security.http import get_csrf_token
from . import sessions  # noqa: E402  (SR-06)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
ph = PasswordHasher()


def hash_password(password):
    return ph.hash(password)


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


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user.role not in roles:
                audit.record("access_denied", g.user.id, path=request.path)
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = User.query.filter_by(email=str(data.get("email", "")).lower()).first()
    try:
        ok = user is not None and ph.verify(user.password_hash, str(data.get("password", "")))
    except VerificationError:
        ok = False
    if not ok:
        audit.record("login_failed", None, email=data.get("email"))
        abort(401)
    sessions.start(user)
    audit.record("login_ok", user.id)
    return jsonify(role=user.role, csrf_token=get_csrf_token())


@bp.post("/logout")
def logout():
    sessions.end()
    return jsonify(ok=True)


@bp.post("/logout-all")
@login_required
def logout_all():
    n = sessions.revoke_all(g.user.id)
    session.clear()
    audit.record("sessions_revoked_all", g.user.id, sessions=n)
    return jsonify(ok=True, ended=n)


@bp.post("/reauth")
@login_required
@limiter.limit("5 per minute")
def reauth():
    """SR-06: confirm the password again before a sensitive change."""
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    try:
        ok = ph.verify(g.user.password_hash, password)
    except VerificationError:
        ok = False
    if not ok:
        audit.record("reauth_failed", g.user.id)
        abort(401, description="password incorrect")
    sessions.confirm_password_now()
    audit.record("reauth_ok", g.user.id)
    return jsonify(ok=True)


@bp.get("/me")
@login_required
def me():
    return jsonify(id=g.user.id, email=g.user.email, role=g.user.role)
