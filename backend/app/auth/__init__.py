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
from ..extensions import db
from ..models import User
from ..security.http import get_csrf_token

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
ph = PasswordHasher()


def hash_password(password):
    return ph.hash(password)


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


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
    session.clear()  # new session on login, stops session fixation
    session["uid"] = user.id
    session.permanent = True
    audit.record("login_ok", user.id, coarse_time=(user.role == "voter"))
    return jsonify(role=user.role, csrf_token=get_csrf_token())


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@login_required
def me():
    return jsonify(id=g.user.id, email=g.user.email, role=g.user.role)
