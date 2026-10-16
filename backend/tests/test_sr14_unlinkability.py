"""SR-14: voter identity and ballots cannot be linked."""
import hashlib

from app.extensions import db
from app.models import BallotToken, CastBallot, Voter

from .conftest import csrf, login, vote

IDENTIFYING = ("voter", "user", "email", "name", "time", "date", "ip", "created", "session")


def test_ballot_tables_have_no_identifying_columns(app):
    for model in (CastBallot, BallotToken):
        for col in model.__table__.columns.keys():
            parts = col.lower().split("_")
            assert not any(w in parts for w in IDENTIFYING), f"{model.__tablename__}.{col}"


def test_identity_and_ballots_are_separate_databases(app):
    with app.app_context():
        assert db.engines[None] is not db.engines["ballots"]
        assert "cast_ballots" not in db.inspect(db.engines[None]).get_table_names()
        assert "voters" not in db.inspect(db.engines["ballots"]).get_table_names()


def test_only_token_hash_is_stored(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]
    with app.app_context():
        row = BallotToken.query.one()
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in row.token_hash


def test_cast_works_without_any_login_session(app, client):
    # vote() casts from a brand new client with no session cookie
    assert vote(app, client, "voter1@test.local").status_code == 200


def test_token_is_single_use(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]
    body = {"ballot_token": token, "ballot": {"house": [1, 2, 3, 4]}}
    h = {"X-CSRF-Token": c}
    assert client.post("/api/ballot/cast", json=body, headers=h).status_code == 200
    assert client.post("/api/ballot/cast", json=body, headers=h).status_code == 403


def test_voter_cannot_get_second_token(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).status_code == 200
    assert client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).status_code == 409


def test_voter_record_keeps_flag_but_no_time(app, client):
    vote(app, client, "voter1@test.local")
    with app.app_context():
        assert Voter.query.first().ballot_issued is True
        # no "voted at" / "issued at" style column (date_of_birth is enrolment data, not voting)
        cols = [c for c in Voter.__table__.columns.keys() if c != "date_of_birth"]
        assert not any("time" in c or "date" in c or c.endswith("_at") for c in cols)


def test_forged_token_rejected(app, client):
    r = client.post("/api/ballot/cast", json={"ballot_token": "x" * 43, "ballot": {"house": [1, 2, 3, 4]}},
                    headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 403


def test_candidate_list_for_voter_division(app, client):
    login(client, "voter1@test.local", "pw-voter")
    r = client.get("/api/ballot/candidates").get_json()
    assert r["division"] == "Melbourne" and len(r["candidates"]) == 4 and r["issued"] is False


def test_candidate_list_needs_voter_role(app, client):
    assert client.get("/api/ballot/candidates").status_code == 401
    login(client, "tally@test.local", "pw-tally")
    assert client.get("/api/ballot/candidates").status_code == 403


def test_invalid_ballot_does_not_burn_token(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]
    h = {"X-CSRF-Token": c}
    bad = client.post("/api/ballot/cast", json={"ballot_token": token, "ballot": {"house": [1]}}, headers=h)
    assert bad.status_code == 400
    ok = client.post("/api/ballot/cast", json={"ballot_token": token, "ballot": {"house": [1, 2, 3, 4]}}, headers=h)
    assert ok.status_code == 200


def test_token_burn_is_a_single_conditional_update(app):
    """Second burn of the same token in the same transaction matches no rows,
    so a racing request can't reuse it."""
    from sqlalchemy import update
    with app.app_context():
        db.session.add(BallotToken(token_hash="a" * 64, division="Melbourne"))
        db.session.commit()
        stmt = (update(BallotToken).where(BallotToken.token_hash == "a" * 64, BallotToken.used.is_(False))
                .values(used=True))
        assert db.session.execute(stmt).rowcount == 1
        assert db.session.execute(stmt).rowcount == 0
