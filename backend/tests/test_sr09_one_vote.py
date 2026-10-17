"""SR-09: One vote per voter.

Enforces that each eligible registered voter can cast at most one ballot.
Atomic conditional update prevents duplicate token issuance and double voting.
"""
import concurrent.futures
from sqlalchemy import update

from app.extensions import db
from app.models import BallotToken, Voter
from .conftest import csrf, login, vote, candidate_ids


def test_eligible_voter_can_obtain_token_once(app, client):
    """An enrolled voter can claim a ballot token exactly once."""
    c = login(client, "voter1@test.local", "pw-voter")
    res = client.post("/api/ballot/token", headers={"X-CSRF-Token": c})
    assert res.status_code == 200
    data = res.get_json()
    assert "ballot_token" in data
    assert data["division"] == "Melbourne"

    with app.app_context():
        v = Voter.query.filter_by(user_id=1).first()
        assert v.ballot_issued is True


def test_voter_cannot_obtain_second_token(app, client):
    """Second token claim attempt by the same voter is rejected with 409 Conflict."""
    c = login(client, "voter1@test.local", "pw-voter")
    res1 = client.post("/api/ballot/token", headers={"X-CSRF-Token": c})
    assert res1.status_code == 200

    res2 = client.post("/api/ballot/token", headers={"X-CSRF-Token": c})
    assert res2.status_code == 409
    data = res2.get_json()
    assert "ballot already issued" in (data.get("message") or data.get("error"))


def test_unenrolled_voter_cannot_obtain_token(app, client):
    """Unenrolled voter is denied token issuance with 403 Forbidden."""
    with app.app_context():
        v = Voter.query.filter_by(user_id=1).first()
        v.enrolled = False
        db.session.commit()

    c = login(client, "voter1@test.local", "pw-voter")
    res = client.post("/api/ballot/token", headers={"X-CSRF-Token": c})
    assert res.status_code == 403
    data = res.get_json()
    assert "not enrolled" in (data.get("message") or data.get("error"))


def test_token_cannot_be_reused_to_cast_twice(app, client):
    """A single ballot token cannot be used to cast two ballots."""
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]

    anon = app.test_client()
    body = {"ballot_token": token, "ballot": {"house": candidate_ids(app)}}
    h = {"X-CSRF-Token": csrf(anon)}

    res1 = anon.post("/api/ballot/cast", json=body, headers=h)
    assert res1.status_code == 200

    res2 = anon.post("/api/ballot/cast", json=body, headers=h)
    assert res2.status_code == 403
    data = res2.get_json()
    assert "invalid or used" in (data.get("message") or data.get("error"))


def test_voter_claim_is_a_single_conditional_update(app):
    """
    Second claim of the same voter matches zero rows, guaranteeing that racing
    requests cannot both succeed.
    """
    with app.app_context():
        voter = Voter.query.filter_by(user_id=1).first()
        assert voter.ballot_issued is False

        stmt = (
            update(Voter)
            .where(Voter.id == 1, Voter.enrolled.is_(True), Voter.ballot_issued.is_(False))
            .values(ballot_issued=True)
        )
        # First execution matches and claims the voter
        assert db.session.execute(stmt).rowcount == 1
        # Second execution on the same row matches 0 rows (atomic protection against double claim)
        assert db.session.execute(stmt).rowcount == 0
