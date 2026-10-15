"""SR-06: server-side sessions, timeouts, revocation, re-authentication."""
from datetime import timedelta

from app.auth.sessions import _now
from app.extensions import db
from app.models import UserSession

from .conftest import csrf, login

ADDRESS = "7 Lygon St, Carlton VIC 3053"


def only_session(app, email_user_id=None):
    with app.app_context():
        return UserSession.query.order_by(UserSession.created_at.desc()).first()


def shift(app, **delta):
    """Move the latest session's timestamps into the past."""
    with app.app_context():
        row = UserSession.query.order_by(UserSession.created_at.desc()).first()
        for field, d in delta.items():
            setattr(row, field, getattr(row, field) - d)
        db.session.commit()


def test_logout_kills_a_copied_cookie(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    stolen = client.get_cookie("session").value
    client.post("/api/auth/logout", headers={"X-CSRF-Token": c})
    attacker = app.test_client()
    attacker.set_cookie("session", stolen, domain="localhost")
    assert attacker.get("/api/auth/me").status_code == 401


def test_idle_timeout(app, client):
    login(client, "voter1@test.local", "pw-voter")
    shift(app, last_seen=timedelta(minutes=16))
    assert client.get("/api/auth/me").status_code == 401


def test_activity_keeps_session_alive(app, client):
    login(client, "voter1@test.local", "pw-voter")
    shift(app, last_seen=timedelta(minutes=10))
    assert client.get("/api/auth/me").status_code == 200


def test_absolute_timeout_even_when_active(app, client):
    login(client, "voter1@test.local", "pw-voter")
    shift(app, created_at=timedelta(hours=9))
    assert client.get("/api/auth/me").status_code == 401


def test_new_staff_login_ends_previous_session(app):
    first, second = app.test_client(), app.test_client()
    login(first, "tally@test.local", "pw-tally")
    login(second, "tally@test.local", "pw-tally")
    assert first.get("/api/auth/me").status_code == 401
    assert second.get("/api/auth/me").status_code == 200


def test_voters_may_have_more_than_one_session(app):
    a, b = app.test_client(), app.test_client()
    login(a, "voter1@test.local", "pw-voter")
    login(b, "voter1@test.local", "pw-voter")
    assert a.get("/api/auth/me").status_code == 200


def test_logout_everywhere(app):
    a, b = app.test_client(), app.test_client()
    login(a, "voter1@test.local", "pw-voter")
    c = login(b, "voter1@test.local", "pw-voter")
    assert b.post("/api/auth/logout-all", headers={"X-CSRF-Token": c}).get_json()["ended"] == 2
    assert a.get("/api/auth/me").status_code == 401


def test_session_id_stored_hashed(app, client):
    login(client, "voter1@test.local", "pw-voter")
    with client.session_transaction() as s:
        sid = s["sid"]
    with app.app_context():
        assert UserSession.query.filter_by(sid_hash=sid).first() is None
        assert UserSession.query.count() == 1


def test_sensitive_change_needs_recent_password(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    shift(app, auth_at=timedelta(minutes=6))
    r = client.put("/api/enrolment/me/address", json={"address": ADDRESS}, headers={"X-CSRF-Token": c})
    assert r.status_code == 401 and r.get_json()["message"] == "reauth_required"
    # still logged in, only the sensitive action is blocked
    assert client.get("/api/enrolment/me").status_code == 200


def test_reauth_unlocks_sensitive_change(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    shift(app, auth_at=timedelta(minutes=6))
    assert client.post("/api/auth/reauth", json={"password": "wrong"}, headers={"X-CSRF-Token": c}).status_code == 401
    assert client.post("/api/auth/reauth", json={"password": "pw-voter"}, headers={"X-CSRF-Token": c}).status_code == 200
    r = client.put("/api/enrolment/me/address", json={"address": ADDRESS}, headers={"X-CSRF-Token": c})
    assert r.status_code == 200


def test_fresh_login_counts_as_recent_auth(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.put("/api/enrolment/me/address", json={"address": ADDRESS},
                      headers={"X-CSRF-Token": c}).status_code == 200


def test_forged_session_id_rejected(app, client):
    with client.session_transaction() as s:
        s["sid"] = "made-up-session-id"
    assert client.get("/api/auth/me").status_code == 401

def test_wrong_password_does_not_unlock_sensitive_change(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    shift(app, auth_at=timedelta(minutes=6))
    h = {"X-CSRF-Token": c}
    assert client.post("/api/auth/reauth", json={"password": "wrong"}, headers=h).status_code == 401
    r = client.put("/api/enrolment/me/address", json={"address": ADDRESS}, headers=h)
    assert r.status_code == 401 and r.get_json()["message"] == "reauth_required"


def test_wrong_reauth_passwords_lock_the_account(app, client):
    """SR-03 and SR-06: guessing the password through /reauth counts towards the lockout."""
    from app.auth import MAX_FAILED_LOGINS
    from .conftest import csrf
    c = login(client, "voter1@test.local", "pw-voter")
    h = {"X-CSRF-Token": c}
    for _ in range(MAX_FAILED_LOGINS):
        assert client.post("/api/auth/reauth", json={"password": "wrong"}, headers=h).status_code == 401
    assert client.get("/api/auth/me").status_code == 401  # every session was ended
    r = client.post("/api/auth/login", json={"email": "voter1@test.local", "password": "pw-voter"},
                    headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 401  # locked, even with the right password
