"""SR-17: dual control for candidate changes and manual exclusion."""
from datetime import timedelta

import pytest

from app.auth import hash_password
from app.extensions import db
from app.models import Candidate, PendingChange, User

from .conftest import csrf, login, vote

REASON = "Court of Disputed Returns order 2026/17"


@pytest.fixture
def delegates(app):
    with app.app_context():
        for n, state in [(1, "VIC"), (2, "VIC"), (3, "NSW")]:
            db.session.add(User(email=f"del{n}@test.local", password_hash=hash_password("pw"), role="delegate", state=state))
        db.session.commit()


def as_delegate(app, n):
    c = app.test_client()
    return c, login(c, f"del{n}@test.local", "pw")


def post(client, token, path, body=None):
    return client.post(path, json=body or {}, headers={"X-CSRF-Token": token})


def first_candidate(app):
    with app.app_context():
        return Candidate.query.order_by(Candidate.ballot_order).first().id


def request_exclude(app, client, token):
    return post(client, token, "/api/candidates/changes",
                {"kind": "exclude", "candidate_id": first_candidate(app), "reason": REASON})


def test_change_needs_second_delegate(app, delegates):
    c1, t1 = as_delegate(app, 1)
    cid = first_candidate(app)
    r = post(c1, t1, "/api/candidates/changes", {"kind": "update", "candidate_id": cid,
                                                  "fields": {"party": "New Party"}, "reason": "Registered name change"})
    assert r.status_code == 201
    with app.app_context():
        assert db.session.get(Candidate, cid).party == "Test"  # nothing changed yet
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{r.get_json()['id']}/approve").status_code == 200
    with app.app_context():
        assert db.session.get(Candidate, cid).party == "New Party"


def test_requester_cannot_approve_own_change(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    r = post(c1, t1, f"/api/candidates/changes/{rid}/approve")
    assert r.status_code == 403 and "second delegate" in r.get_json()["message"]


def test_other_state_delegate_cannot_approve_or_see(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c3, t3 = as_delegate(app, 3)
    assert post(c3, t3, f"/api/candidates/changes/{rid}/approve").status_code == 404
    assert c3.get("/api/candidates").get_json()["pending"] == []


def test_update_frozen_once_voting_started(app, delegates):
    vote(app, app.test_client(), "voter1@test.local")
    c1, t1 = as_delegate(app, 1)
    r = post(c1, t1, "/api/candidates/changes", {"kind": "update", "candidate_id": first_candidate(app),
                                                  "fields": {"name": "Someone Else"}, "reason": "Late name change"})
    assert r.status_code == 409


def test_exclusion_allowed_after_voting(app, delegates):
    vote(app, app.test_client(), "voter1@test.local")
    c1, t1 = as_delegate(app, 1)
    assert request_exclude(app, c1, t1).status_code == 201


def test_request_expires_after_24_hours(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    with app.app_context():
        p = db.session.get(PendingChange, rid)
        p.requested_at -= timedelta(hours=25)
        db.session.commit()
    c2, t2 = as_delegate(app, 2)
    r = post(c2, t2, f"/api/candidates/changes/{rid}/approve")
    assert r.status_code == 409 and "expired" in r.get_json()["message"]


def test_cannot_apply_twice(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/approve").status_code == 200
    assert post(c2, t2, f"/api/candidates/changes/{rid}/approve").status_code == 409


def test_reject(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/reject").get_json()["status"] == "rejected"
    with app.app_context():
        assert db.session.get(Candidate, first_candidate(app)).excluded is False


@pytest.mark.parametrize("body,code", [
    ({"kind": "delete", "candidate_id": 1, "reason": REASON}, 400),
    ({"kind": "exclude", "candidate_id": 1, "reason": "short"}, 400),
    ({"kind": "exclude", "candidate_id": 9999, "reason": REASON}, 404),
    ({"kind": "exclude", "candidate_id": "1", "reason": REASON}, 404),
    ({"kind": "update", "candidate_id": 1, "fields": {"excluded": False}, "reason": REASON}, 400),
    ({"kind": "update", "candidate_id": 1, "fields": {"ballot_order": "1"}, "reason": REASON}, 400),
    ({"kind": "create", "fields": {"name": "X"}, "reason": REASON}, 400),
])
def test_bad_requests(app, delegates, body, code):
    c1, t1 = as_delegate(app, 1)
    assert post(c1, t1, "/api/candidates/changes", body).status_code == code


def test_create_candidate_with_approval(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = post(c1, t1, "/api/candidates/changes", {"kind": "create", "reason": "Late nomination accepted",
               "fields": {"name": "E. Evans", "party": "Party E", "division": "Melbourne", "ballot_order": 5}}).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/approve").status_code == 200
    with app.app_context():
        assert Candidate.query.filter_by(name="E. Evans", state="VIC").count() == 1


def test_only_delegates(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.get("/api/candidates").status_code == 403
    assert post(client, c, "/api/candidates/changes", {}).status_code == 403


def test_exclusion_changes_the_count(app, client, delegates):
    ids = [first_candidate(app)] + [i for i in range(1, 5) if i != first_candidate(app)]
    for e in ["voter1@test.local", "voter2@test.local"]:
        vote(app, app.test_client(), e, ids)
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/approve").status_code == 200
    from app.tally import run_tally
    with app.app_context():
        result = run_tally()
    melb = result["first_preferences"]["Melbourne"]
    assert "Adams" not in melb and sum(melb.values()) == 2 and result["excluded"] == ["Adams"]


def test_only_one_pending_change_per_candidate(app, delegates):
    c1, t1 = as_delegate(app, 1)
    assert request_exclude(app, c1, t1).status_code == 201
    c2, t2 = as_delegate(app, 2)
    r = post(c2, t2, "/api/candidates/changes", {"kind": "update", "candidate_id": first_candidate(app),
                                                  "fields": {"party": "Other"}, "reason": "Registered name change"})
    assert r.status_code == 409 and "already has a change" in r.get_json()["message"]


def test_expired_request_does_not_block_new_one(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    with app.app_context():
        db.session.get(PendingChange, rid).requested_at -= timedelta(hours=25)
        db.session.commit()
    assert request_exclude(app, c1, t1).status_code == 201


def test_ballot_position_clash_refused(app, delegates):
    c1, t1 = as_delegate(app, 1)
    r = post(c1, t1, "/api/candidates/changes", {"kind": "create", "reason": "Late nomination accepted",
             "fields": {"name": "E. Evans", "division": "Melbourne", "ballot_order": 1}})
    assert r.status_code == 409 and "ballot position 1" in r.get_json()["message"]


def test_position_taken_between_request_and_approval(app, delegates):
    c1, t1 = as_delegate(app, 1)
    body = {"kind": "create", "reason": "Late nomination accepted",
            "fields": {"name": "E. Evans", "division": "Melbourne", "ballot_order": 5}}
    first = post(c1, t1, "/api/candidates/changes", body).get_json()["id"]
    second = post(c1, t1, "/api/candidates/changes", dict(body, fields=dict(body["fields"], name="F. Fox"))).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{first}/approve").status_code == 200
    r = post(c2, t2, f"/api/candidates/changes/{second}/approve")
    assert r.status_code == 409 and "taken since" in r.get_json()["message"]
    with app.app_context():
        assert Candidate.query.filter_by(division="Melbourne", ballot_order=5).count() == 1


def test_excluded_candidate_cannot_be_changed(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    post(c2, t2, f"/api/candidates/changes/{rid}/approve")
    r = post(c1, t1, "/api/candidates/changes", {"kind": "update", "candidate_id": first_candidate(app),
                                                  "fields": {"party": "Other"}, "reason": "Registered name change"})
    assert r.status_code == 409


def test_requester_can_withdraw_own_request(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    assert post(c1, t1, f"/api/candidates/changes/{rid}/withdraw").get_json()["status"] == "withdrawn"
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/approve").status_code == 409
    with app.app_context():
        assert db.session.get(Candidate, first_candidate(app)).excluded is False


def test_only_requester_can_withdraw(app, delegates):
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    c2, t2 = as_delegate(app, 2)
    assert post(c2, t2, f"/api/candidates/changes/{rid}/withdraw").status_code == 403


def test_dual_control_events_are_audited(app, delegates):
    import json
    from app.models import AuditEvent
    c1, t1 = as_delegate(app, 1)
    rid = request_exclude(app, c1, t1).get_json()["id"]
    post(c1, t1, f"/api/candidates/changes/{rid}/approve")  # self-approval attempt
    c2, t2 = as_delegate(app, 2)
    post(c2, t2, f"/api/candidates/changes/{rid}/approve")
    with app.app_context():
        events = [e.event for e in AuditEvent.query.order_by(AuditEvent.seq)]
        applied = AuditEvent.query.filter_by(event="candidate_change_applied").one()
    assert {"candidate_change_requested", "dual_control_violation", "candidate_change_applied"} <= set(events)
    details = json.loads(applied.details)
    assert details["before"]["excluded"] is False and details["after"]["excluded"] is True
