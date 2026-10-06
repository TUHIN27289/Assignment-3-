"""Authentication and access checks.

SR-02: permission_required() checks the logged-in user's role against the
permission table in security/rbac.py. The role is read from the database on
every request, never trusted from the client or cached in the session.
SR-01 (MFA), SR-03 (lockout/rate limiting) and SR-06 (session management)
extend this.
"""
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from flask import Blueprint, abort, g, jsonify, request, session

from .. import audit
from ..extensions import db
from ..models import User
from ..security.http import get_csrf_token
from ..security.rbac import has_permission, public

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
@public
def logout():
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@permission_required("self:read")
def me():
    return jsonify(id=g.user.id, email=g.user.email, role=g.user.role)
