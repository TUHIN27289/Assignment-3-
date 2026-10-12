"""SR-19: voters issued vs tokens vs ballots must reconcile."""
import uuid

from app.extensions import db
from app.models import BallotToken, CastBallot, IntegrityAlert, Voter
from app.tally import run_tally
from app.tally.reconcile import reconcile

from .conftest import login, vote


def cast(app, *emails):
    for e in emails:
        assert vote(app, app.test_client(), e).status_code == 200


def stuff_ballot(division="Melbourne"):
    db.session.add(CastBallot(seq=999, ballot_id=str(uuid.uuid4()), election_id="federal-2026", division=division,
                              ciphertext=b"x", nonce=b"n" * 12, wrapped_key=b"k", digest="d" * 64, chain_mac="m" * 64))
    db.session.commit()


def test_clean_election_reconciles(app):
    cast(app, "voter1@test.local", "voter2@test.local")
    with app.app_context():
        r = reconcile()
    assert r["ok"] and r["voters_issued"] == r["tokens_issued"] == r["ballots_stored"] == 2


def test_abandoned_token_is_reported_not_an_error(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    client.post("/api/ballot/token", headers={"X-CSRF-Token": c})  # never cast
    with app.app_context():
        r = reconcile()
    assert r["ok"] and r["tokens_unused"] == 1


def test_ballot_stuffing_detected(app):
    cast(app, "voter1@test.local")
    with app.app_context():
        stuff_ballot()
        r = reconcile()
    assert not r["ok"] and any("ballots stored" in p for p in r["problems"])


def test_forged_token_detected(app):
    with app.app_context():
        db.session.add(BallotToken(token_hash="f" * 64, division="Melbourne"))
        db.session.commit()
        r = reconcile()
    assert not r["ok"] and any("tokens exist" in p for p in r["problems"])


def test_hiding_that_a_voter_voted_is_detected(app):
    cast(app, "voter1@test.local")
    with app.app_context():
        Voter.query.filter_by(ballot_issued=True).one().ballot_issued = False  # so they could vote again
        db.session.commit()
        assert not reconcile()["ok"]


def test_stuffing_into_one_division_detected(app):
    """Totals can match while one seat is stuffed, so divisions are checked too."""
    cast(app, "voter1@test.local", "voter2@test.local")
    with app.app_context():
        b = CastBallot.query.first()
        b.division = "Kooyong"
        db.session.commit()
        r = reconcile()
    assert any(p.startswith("Kooyong") for p in r["problems"])


def test_mismatch_raises_alert(app):
    cast(app, "voter1@test.local")
    with app.app_context():
        stuff_ballot()
        reconcile()
        assert IntegrityAlert.query.filter(IntegrityAlert.reason.like("reconciliation:%")).count() >= 1


def test_cli_exit_codes(app):
    runner = app.test_cli_runner()
    ok = runner.invoke(args=["reconcile"])
    assert ok.exit_code == 0 and "OK" in ok.output
    with app.app_context():
        stuff_ballot()
    bad = runner.invoke(args=["reconcile"])
    assert bad.exit_code == 1 and "MISMATCH" in bad.output


def test_tally_includes_reconciliation(app):
    cast(app, "voter1@test.local")
    with app.app_context():
        assert run_tally()["reconciliation"]["ok"] is True


def test_endpoint_for_tally_and_auditor_only(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.get("/api/tally/reconcile").status_code == 403
    client.post("/api/auth/logout", headers={"X-CSRF-Token": c})
    login(client, "tally@test.local", "pw-tally")
    assert client.get("/api/tally/reconcile").get_json()["ok"] is True
