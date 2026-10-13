"""SR-01: TOTP MFA for all staff accounts."""
import time

import pyotp
import pytest

from app.auth.mfa import check_code, decrypt_secret
from app.extensions import db
from app.models import AuditEvent, User

from .conftest import csrf, login, totp_code

EMAIL, PW = "tally@test.local", "pw-tally"


def password_step(client, email=EMAIL, pw=PW):
    r = client.post("/api/auth/login", json={"email": email, "password": pw},
                    headers={"X-CSRF-Token": csrf(client)})
    return r.get_json()


def enrol(client):
    token = password_step(client)["csrf_token"]
    secret = client.post("/api/auth/mfa/setup", headers={"X-CSRF-Token": token}).get_json()["secret"]
    return token, secret


def get_user(app):
    with app.app_context():
        return User.query.filter_by(email=EMAIL).one()


def test_password_alone_gives_no_access_to_staff(app, client):
    data = password_step(client)
    assert data == {"mfa_setup_required": True, "csrf_token": data["csrf_token"]}
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/tally/run", headers={"X-CSRF-Token": data["csrf_token"]}).status_code == 401


def test_voters_log_in_without_mfa(app, client):
    r = client.post("/api/auth/login", json={"email": "voter1@test.local", "password": "pw-voter"},
                    headers={"X-CSRF-Token": csrf(client)}).get_json()
    assert r["role"] == "voter"


def test_first_login_enrols_then_later_logins_ask_for_code(app, client):
    login(client, EMAIL, PW)
    assert get_user(app).mfa_enabled
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    assert password_step(client).get("mfa_required") is True


def test_setup_gives_standard_otpauth_uri(app, client):
    token = password_step(client)["csrf_token"]
    r = client.post("/api/auth/mfa/setup", headers={"X-CSRF-Token": token}).get_json()
    assert r["otpauth_uri"].startswith("otpauth://totp/") and r["secret"] in r["otpauth_uri"]


def test_secret_is_encrypted_at_rest(app, client):
    _, secret = enrol(client)
    u = get_user(app)
    assert secret.encode() not in u.mfa_secret_enc
    with app.app_context():
        assert decrypt_secret(u.id, u.mfa_secret_enc) == secret


def test_secret_cannot_be_moved_to_another_user(app, client):
    from cryptography.exceptions import InvalidTag
    enrol(client)
    u = get_user(app)
    with app.app_context(), pytest.raises(InvalidTag):
        decrypt_secret(u.id + 1, u.mfa_secret_enc)


def test_wrong_code_refused(app, client):
    token, _ = enrol(client)
    r = client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers={"X-CSRF-Token": token})
    assert r.status_code == 401 and client.get("/api/auth/me").status_code == 401


def test_code_cannot_be_replayed(app, client):
    token, secret = enrol(client)
    code = pyotp.TOTP(secret).now()
    assert client.post("/api/auth/mfa/verify", json={"code": code}, headers={"X-CSRF-Token": token}).status_code == 200
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    token = password_step(client)["csrf_token"]
    assert client.post("/api/auth/mfa/verify", json={"code": code}, headers={"X-CSRF-Token": token}).status_code == 401


def test_old_code_outside_window_refused(app, client):
    _, secret = enrol(client)
    with app.app_context():
        u = User.query.filter_by(email=EMAIL).one()
        old = pyotp.TOTP(secret).at(time.time() - 120)
        assert check_code(u, old) is False


def test_wrong_codes_lock_the_account(app, client):
    token, _ = enrol(client)
    for _ in range(5):
        client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers={"X-CSRF-Token": token})
    assert get_user(app).locked_until is not None


def test_pending_state_expires(app, client, monkeypatch):
    token, secret = enrol(client)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 301)
    r = client.post("/api/auth/mfa/verify", json={"code": totp_code(secret, client, EMAIL)},
                    headers={"X-CSRF-Token": token})
    assert r.status_code == 401


def test_cannot_reenrol_once_enabled(app, client):
    login(client, EMAIL, PW)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    token = password_step(client)["csrf_token"]
    assert client.post("/api/auth/mfa/setup", headers={"X-CSRF-Token": token}).status_code == 409


def test_mfa_events_are_audited(app, client):
    login(client, EMAIL, PW)
    with app.app_context():
        names = [e.event for e in AuditEvent.query.order_by(AuditEvent.seq)]
    assert names[-3:] == ["mfa_setup_started", "mfa_enabled", "login_ok"]
