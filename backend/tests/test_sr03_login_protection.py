"""SR-03: Argon2id hashing, lockout, rate limiting, enumeration resistance, logging."""
from datetime import datetime, timedelta, timezone

import pytest

from app import auth
from app.extensions import db
from app.models import AuditEvent, User

from .conftest import csrf

EMAIL, GOOD = "tally@test.local", "pw-tally"


def attempt(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password},
                       headers={"X-CSRF-Token": csrf(client)})


def user(app):
    with app.app_context():
        return User.query.filter_by(email=EMAIL).one()


def test_passwords_stored_as_argon2id(app):
    assert user(app).password_hash.startswith("$argon2id$")


def test_lockout_after_five_wrong_passwords(app, client):
    for _ in range(5):
        assert attempt(client, EMAIL, "wrong").status_code == 401
    assert user(app).locked_until is not None
    # even the right password is refused while locked
    assert attempt(client, EMAIL, GOOD).status_code == 401


def test_lock_expires(app, client):
    for _ in range(5):
        attempt(client, EMAIL, "wrong")
    with app.app_context():
        u = User.query.filter_by(email=EMAIL).one()
        u.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
        db.session.commit()
    assert attempt(client, EMAIL, GOOD).status_code == 200


def test_success_resets_counter(app, client):
    for _ in range(4):
        attempt(client, EMAIL, "wrong")
    assert attempt(client, EMAIL, GOOD).status_code == 200
    assert user(app).failed_logins == 0


def test_same_response_for_unknown_wrong_and_locked(app, client):
    unknown = attempt(client, "nobody@test.local", "x").get_json()
    wrong = attempt(client, EMAIL, "wrong").get_json()
    for _ in range(4):
        attempt(client, EMAIL, "wrong")
    locked = attempt(client, EMAIL, GOOD).get_json()
    assert unknown == wrong == locked


def test_unknown_email_still_runs_password_hash(app, client, monkeypatch):
    calls = []
    real = auth._verify
    monkeypatch.setattr(auth, "_verify", lambda h, p: calls.append(h) or real(h, p))
    attempt(client, "nobody@test.local", "whatever")
    assert calls == [auth._DUMMY_HASH]


def test_rate_limit_per_ip(app, client):
    codes = [attempt(client, "nobody@test.local", "x").status_code for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429


def test_every_attempt_is_audited(app, client):
    attempt(client, "voter1@test.local", "wrong")
    attempt(client, "voter1@test.local", "pw-voter")
    with app.app_context():
        events = [(e.event, e.details) for e in AuditEvent.query.order_by(AuditEvent.seq)]
    assert events[0][0] == "login_failed" and "wrong password" in events[0][1]
    assert events[1][0] == "login_ok"


def test_old_hash_parameters_are_upgraded_on_login(app, client):
    from argon2 import PasswordHasher
    weak = PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1).hash(GOOD)
    with app.app_context():
        User.query.filter_by(email=EMAIL).one().password_hash = weak
        db.session.commit()
    assert attempt(client, EMAIL, GOOD).status_code == 200
    assert user(app).password_hash != weak and "m=65536" in user(app).password_hash


@pytest.mark.parametrize("pw,ok", [
    ("short", False),
    ("password1234", False),
    ("jsmith-is-my-password", False),
    ("correct horse battery", True),
])
def test_password_policy(pw, ok):
    assert (auth.check_password_policy(pw, "jsmith@aec.gov.au") == []) is ok


def test_locked_account_still_runs_password_hash(app, client, monkeypatch):
    """A locked account must do the same hashing work as a wrong password.
    If it refuses faster, the response time reveals that the account exists."""
    for _ in range(5):
        attempt(client, EMAIL, "wrong")
    calls = []
    real = auth._verify
    monkeypatch.setattr(auth, "_verify", lambda h, p: calls.append(h) or real(h, p))
    attempt(client, EMAIL, GOOD)
    assert len(calls) == 1
