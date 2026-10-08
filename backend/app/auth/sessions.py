"""SR-06: session management.

Flask's default session is just a signed cookie, so "logging out" only
deletes the browser's copy. Anyone who copied the cookie could keep using
it. Here every login creates a row in user_sessions, the cookie only
carries a random session id, and each request is checked against that row:

  - idle timeout 15 min, absolute timeout 8 h (a working shift)
  - logout revokes the row, so a copied cookie stops working at once
  - "sign out everywhere" revokes all of a user's sessions
  - staff accounts get one active session: a new login ends the old one
  - only the SHA-256 of the session id is stored, so a database leak
    doesn't hand out live sessions
  - sensitive changes (electoral roll, address, exports) need the password
    to have been entered in the last 5 minutes (re-authentication)
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, current_app, g, session
from sqlalchemy import update

from .. import audit
from ..extensions import db
from ..models import User, UserSession

STAFF_ROLES = {"enrolment_officer", "delegate", "tally_officer", "auditor"}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


def start(user):
    """Call after the user has fully authenticated."""
    if user.role in STAFF_ROLES:
        ended = revoke_all(user.id)
        if ended:
            audit.record("session_ended_by_new_login", user.id, sessions=ended)
    sid = secrets.token_urlsafe(32)
    now = _now()
    db.session.add(UserSession(sid_hash=_hash(sid), user_id=user.id, created_at=now, last_seen=now, auth_at=now))
    db.session.commit()
    session.clear()  # new cookie on login, stops session fixation
    session["sid"] = sid
    session.permanent = True


def _row():
    sid = session.get("sid")
    return db.session.get(UserSession, _hash(sid)) if isinstance(sid, str) else None


def current_session_user():
    row = _row()
    if row is None or row.revoked:
        return None
    now = _now()
    cfg = current_app.config
    if now - row.last_seen > cfg["SESSION_IDLE_TIMEOUT"] or now - row.created_at > cfg["SESSION_ABSOLUTE_TIMEOUT"]:
        row.revoked = True
        db.session.commit()
        session.clear()
        return None
    if now - row.last_seen > timedelta(seconds=30):  # don't write on every single request
        row.last_seen = now
        db.session.commit()
    g.session_row = row
    return db.session.get(User, row.user_id)


def end():
    row = _row()
    if row is not None and not row.revoked:
        row.revoked = True
        db.session.commit()
    session.clear()


def revoke_all(user_id):
    n = db.session.execute(update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked.is_(False))
                           .values(revoked=True)).rowcount
    db.session.commit()
    return n


def confirm_password_now():
    g.session_row.auth_at = _now()
    db.session.commit()


def recent_auth_required(view):
    """Use after the login/role decorator on routes that change sensitive data."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        row = getattr(g, "session_row", None)
        if row is None or _now() - row.auth_at > current_app.config["REAUTH_WINDOW"]:
            abort(401, description="reauth_required")
        return view(*args, **kwargs)
    return wrapper

def test_wrong_password_does_not_unlock_sensitive_change(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    shift(app, auth_at=timedelta(minutes=6))
    h = {"X-CSRF-Token": c}
    assert client.post("/api/auth/reauth", json={"password": "wrong"}, headers=h).status_code == 401
    r = client.put("/api/enrolment/me/address", json={"address": ADDRESS}, headers=h)
    assert r.status_code == 401 and r.get_json()["message"] == "reauth_required"
