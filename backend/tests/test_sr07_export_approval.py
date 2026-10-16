"""SR-07: bulk export of elector records needs a second officer."""
import csv
import io
from datetime import timedelta

import pytest

from app.auth import hash_password
from app.extensions import db
from app.models import AuditEvent, ExportRequest, User, UserSession, Voter

from .conftest import login

REASON = "Annual roll review for Melbourne"


@pytest.fixture
def officers(app):
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 2  # 3 voters in the test DB, so the full roll is "bulk"
    with app.app_context():
        for n in (1, 2):
            db.session.add(User(email=f"off{n}@test.local", password_hash=hash_password("pw"), role="enrolment_officer"))
        db.session.commit()


def officer(app, n):
    c = app.test_client()
    return c, login(c, f"off{n}@test.local", "pw")


def ask(client, token, **body):
    return client.post("/api/enrolment/exports", json={"reason": REASON, **body}, headers={"X-CSRF-Token": token})


def audit_entries(app):
    """Every audit entry as (event, details), read from the audit database (SR-04)."""
    with app.app_context():
        return [(e.event, e.details) for e in AuditEvent.query.order_by(AuditEvent.seq)]


def rows(resp):
    return list(csv.reader(io.StringIO(resp.get_data(as_text=True))))


def test_small_export_needs_no_second_officer(app, officers):
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 500
    c1, t1 = officer(app, 1)
    r = ask(c1, t1).get_json()
    assert r["status"] == "approved"
    d = c1.get(f"/api/enrolment/exports/{r['id']}/download")
    assert d.status_code == 200 and len(rows(d)) == 4  # header + 3 voters


def test_bulk_export_waits_for_second_officer(app, officers):
    c1, t1 = officer(app, 1)
    r = ask(c1, t1).get_json()
    assert r["status"] == "pending"
    assert c1.get(f"/api/enrolment/exports/{r['id']}/download").status_code == 409


def test_requester_cannot_approve_own_export(app, officers):
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    r = c1.post(f"/api/enrolment/exports/{rid}/approve", headers={"X-CSRF-Token": t1})
    assert r.status_code == 403


def test_second_officer_approves_then_single_download(app, officers):
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    c2, t2 = officer(app, 2)
    assert c2.post(f"/api/enrolment/exports/{rid}/approve", headers={"X-CSRF-Token": t2}).status_code == 200
    assert c2.get(f"/api/enrolment/exports/{rid}/download").status_code == 404  # approver can't download
    first = c1.get(f"/api/enrolment/exports/{rid}/download")
    assert first.status_code == 200 and first.headers["Content-Disposition"].startswith("attachment")
    assert c1.get(f"/api/enrolment/exports/{rid}/download").status_code == 409  # only once


def test_rejected_export_cannot_be_downloaded(app, officers):
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    c2, t2 = officer(app, 2)
    c2.post(f"/api/enrolment/exports/{rid}/reject", headers={"X-CSRF-Token": t2})
    assert c1.get(f"/api/enrolment/exports/{rid}/download").status_code == 409


def test_request_expires(app, officers):
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    with app.app_context():
        db.session.get(ExportRequest, rid).requested_at -= timedelta(hours=25)
        db.session.commit()
    c2, t2 = officer(app, 2)
    assert c2.post(f"/api/enrolment/exports/{rid}/approve", headers={"X-CSRF-Token": t2}).status_code == 409


def test_roll_growth_after_approval_blocks_download(app, officers):
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 3
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]  # 3 records, under threshold
    with app.app_context():
        u = User(email="late@test.local", password_hash="x", role="voter")
        db.session.add(u)
        db.session.flush()
        db.session.add(Voter(user_id=u.id, full_name="Late Voter", division="Melbourne", enrolled=True))
        db.session.commit()
    assert c1.get(f"/api/enrolment/exports/{rid}/download").status_code == 409


def test_csv_formula_injection_escaped(app, officers):
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 500
    with app.app_context():
        db.session.get(Voter, 1).full_name = '=HYPERLINK("http://evil.example","click")'
        db.session.commit()
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    data = rows(c1.get(f"/api/enrolment/exports/{rid}/download"))
    assert data[1][1].startswith("'=")


def test_reason_required_and_reauth_required(app, officers):
    c1, t1 = officer(app, 1)
    assert c1.post("/api/enrolment/exports", json={"reason": "x"}, headers={"X-CSRF-Token": t1}).status_code == 400
    with app.app_context():
        for s in UserSession.query.all():
            s.auth_at -= timedelta(minutes=10)
        db.session.commit()
    r = ask(c1, t1)
    assert r.status_code == 401 and r.get_json()["message"] == "reauth_required"


def test_export_is_audited_with_count_not_data(app, officers):
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 500
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    c1.get(f"/api/enrolment/exports/{rid}/download")
    entries = audit_entries(app)
    exported = [details for event, details in entries if event == "pii_export"]
    assert len(exported) == 1 and '"records":3' in exported[0]
    assert not any("Voter 1" in details for _, details in entries)


def test_voters_cannot_export(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert ask(client, c).status_code == 403


def test_threshold_boundary_is_inclusive(app, officers):
    c1, t1 = officer(app, 1)
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 3
    assert ask(c1, t1).get_json()["status"] == "approved"  # exactly 3 records: no second officer needed
    app.config["EXPORT_APPROVAL_THRESHOLD"] = 2
    assert ask(c1, t1).get_json()["status"] == "pending"  # 3 records, one over the limit


def test_decided_request_cannot_be_decided_again(app, officers):
    c1, t1 = officer(app, 1)
    rid = ask(c1, t1).get_json()["id"]
    c2, t2 = officer(app, 2)
    assert c2.post(f"/api/enrolment/exports/{rid}/approve", headers={"X-CSRF-Token": t2}).status_code == 200
    assert c2.post(f"/api/enrolment/exports/{rid}/reject", headers={"X-CSRF-Token": t2}).status_code == 409
    assert c2.post(f"/api/enrolment/exports/{rid}/approve", headers={"X-CSRF-Token": t2}).status_code == 409
