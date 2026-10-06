import pytest
from flask.testing import FlaskClient

from app import create_app
from app.auth import hash_password
from app.config import TestConfig
from app.extensions import db
from app.models import Candidate, User, Voter

DIVISION = "Melbourne"


class HttpsClient(FlaskClient):
    """Every test request goes over https, like the real deployment."""
    def open(self, *args, **kwargs):
        kwargs.setdefault("base_url", "https://localhost")
        return super().open(*args, **kwargs)


@pytest.fixture
def app(tmp_path):
    class Cfg(TestConfig):
        KEY_DIR = str(tmp_path / "keys")

    app = create_app(Cfg)
    app.test_client_class = HttpsClient
    with app.app_context():
        for i, name in enumerate(["Adams", "Brown", "Chen", "Davis"], start=1):
            db.session.add(Candidate(name=name, party="Test", division=DIVISION, ballot_order=i))
        for n in range(1, 4):
            u = User(email=f"voter{n}@test.local", password_hash=hash_password("pw-voter"), role="voter")
            db.session.add(u)
            db.session.flush()
            db.session.add(Voter(user_id=u.id, full_name=f"Voter {n}", division=DIVISION, enrolled=True))
        db.session.add(User(email="tally@test.local", password_hash=hash_password("pw-tally"), role="tally_officer"))
        db.session.commit()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    return client.get("/api/auth/csrf").get_json()["csrf_token"]


def login(client, email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password},
                    headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["csrf_token"]


def candidate_ids(app):
    with app.app_context():
        return [c.id for c in Candidate.query.order_by(Candidate.ballot_order)]


def vote(app, client, email, prefs=None):
    """Full voting flow: log in, get token, cast anonymously in a fresh client."""
    token_csrf = login(client, email, "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": token_csrf}).get_json()["ballot_token"]
    anon = app.test_client()
    r = anon.post("/api/ballot/cast", json={"ballot_token": token, "ballot": {"house": prefs or candidate_ids(app)}},
                  headers={"X-CSRF-Token": csrf(anon)})
    return r
