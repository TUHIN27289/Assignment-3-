"""SR-05: voter personal data encrypted at rest."""
import logging
from datetime import date

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import text

from app.auth import hash_password
from app.extensions import db
from app.models import User, Voter

from .conftest import csrf, login

NAME, ADDRESS = "Charlotte Nguyen", "42 Collins St, Melbourne VIC 3000"


@pytest.fixture
def officer(app):
    with app.app_context():
        db.session.add(User(email="officer@test.local", password_hash=hash_password("pw"), role="enrolment_officer"))
        db.session.commit()


def raw(app, column, voter_id=1):
    with app.app_context():
        return db.session.execute(text(f"SELECT {column} FROM voters WHERE id = :i"), {"i": voter_id}).scalar()


def set_details(app):
    with app.app_context():
        v = db.session.get(Voter, 1)
        v.full_name, v.address, v.date_of_birth = NAME, ADDRESS, "1990-05-17"
        db.session.commit()


def test_database_holds_ciphertext_only(app):
    set_details(app)
    for col, plain in [("full_name", NAME), ("address", ADDRESS), ("date_of_birth", "1990-05-17")]:
        stored = raw(app, col)
        assert isinstance(stored, bytes) and stored.startswith(b"v1")
        assert plain.encode() not in stored


def test_orm_reads_plaintext(app):
    set_details(app)
    with app.app_context():
        v = db.session.get(Voter, 1)
        assert (v.full_name, v.address) == (NAME, ADDRESS)


def test_same_value_encrypts_differently(app):
    with app.app_context():
        for i in (1, 2):
            db.session.get(Voter, i).address = ADDRESS
        db.session.commit()
    assert raw(app, "address", 1) != raw(app, "address", 2)


def test_value_moved_to_another_column_does_not_decrypt(app):
    set_details(app)
    with app.app_context():
        db.session.execute(text("UPDATE voters SET address = full_name WHERE id = 1"))
        db.session.commit()
        db.session.expire_all()
        with pytest.raises(InvalidTag):
            db.session.get(Voter, 1).address


def test_tampered_value_does_not_decrypt(app):
    set_details(app)
    stored = raw(app, "address")
    with app.app_context():
        db.session.execute(text("UPDATE voters SET address = :b WHERE id = 1"),
                           {"b": stored[:-1] + bytes([stored[-1] ^ 1])})
        db.session.commit()
        db.session.expire_all()
        with pytest.raises(InvalidTag):
            db.session.get(Voter, 1).address


def test_voter_sees_own_details(app, client):
    set_details(app)
    login(client, "voter1@test.local", "pw-voter")
    r = client.get("/api/enrolment/me").get_json()
    assert r["full_name"] == NAME and r["enrolled"] is True


def test_address_update_is_audited_without_the_address(app, client, caplog):
    c = login(client, "voter1@test.local", "pw-voter")
    with caplog.at_level(logging.INFO, logger="audit"):
        r = client.put("/api/enrolment/me/address", json={"address": ADDRESS}, headers={"X-CSRF-Token": c})
    assert r.status_code == 200 and r.get_json()["address"] == ADDRESS
    assert "address_changed" in caplog.text and "Collins" not in caplog.text


def test_officer_can_list_and_reads_are_audited(app, client, officer, caplog):
    set_details(app)
    login(client, "officer@test.local", "pw")
    with caplog.at_level(logging.INFO, logger="audit"):
        r = client.get("/api/enrolment/voters?division=Melbourne").get_json()
    assert any(v["full_name"] == NAME for v in r["voters"])
    assert "pii_read" in caplog.text and NAME not in caplog.text


def test_voter_cannot_list_others(app, client):
    login(client, "voter1@test.local", "pw-voter")
    assert client.get("/api/enrolment/voters").status_code == 403


def test_officer_registers_citizen(app, client, officer):
    c = login(client, "officer@test.local", "pw")
    r = client.post("/api/enrolment/voters", headers={"X-CSRF-Token": c}, json={
        "email": "new@test.local", "full_name": NAME, "date_of_birth": "1995-02-03",
        "address": ADDRESS, "division": "Melbourne"})
    assert r.status_code == 201
    temp = r.get_json()["temporary_password"]
    fresh = app.test_client()
    login(fresh, "new@test.local", temp)
    assert fresh.get("/api/enrolment/me").get_json()["full_name"] == NAME


@pytest.mark.parametrize("override,code", [
    ({"date_of_birth": f"{date.today().year - 17}-01-01"}, 403),
    ({"date_of_birth": "not-a-date"}, 400),
    ({"email": "not-an-email"}, 400),
    ({"email": "voter1@test.local"}, 409),
    ({"division": "Robert'); DROP TABLE voters;--"}, 400),
    ({"address": "x"}, 400),
])
def test_register_validation(app, client, officer, override, code):
    c = login(client, "officer@test.local", "pw")
    body = {"email": "a@test.local", "full_name": NAME, "date_of_birth": "1990-01-01",
            "address": ADDRESS, "division": "Melbourne", **override}
    assert client.post("/api/enrolment/voters", json=body, headers={"X-CSRF-Token": c}).status_code == code


def test_self_enrolment(app, client):
    with app.app_context():
        db.session.get(Voter, 1).enrolled = False
        db.session.commit()
    c = login(client, "voter1@test.local", "pw-voter")
    r = client.post("/api/enrolment/me/enrol", json={"date_of_birth": "1990-01-01", "address": ADDRESS},
                    headers={"X-CSRF-Token": c})
    assert r.status_code == 200 and r.get_json()["enrolled"] is True
    assert client.post("/api/enrolment/me/enrol", json={}, headers={"X-CSRF-Token": c}).status_code == 409


def test_no_key_in_database(app):
    set_details(app)
    key = app.extensions["keys"].pii_key()
    with app.app_context():
        for table in ("voters", "users"):
            for row in db.session.execute(text(f"SELECT * FROM {table}")):
                assert not any(isinstance(c, bytes) and key in c for c in row)
