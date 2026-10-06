"""SR-04: tamper-evident, append-only audit log."""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from app import audit
from app.auth import hash_password
from app.extensions import db
from app.models import AuditEvent, User

from .conftest import csrf, login


@pytest.fixture
def auditor(app):
    with app.app_context():
        db.session.add(User(email="auditor@test.local", password_hash=hash_password("pw-audit"), role="auditor"))
        db.session.commit()


def events(app):
    with app.app_context():
        return AuditEvent.query.order_by(AuditEvent.seq).all()


def test_logins_are_recorded(app, client):
    client.post("/api/auth/login", json={"email": "tally@test.local", "password": "wrong"},
                headers={"X-CSRF-Token": csrf(client)})
    login(client, "tally@test.local", "pw-tally")
    names = [e.event for e in events(app)]
    assert "login_failed" in names and "login_ok" in names


def test_failed_request_still_audited(app, client):
    """The 401 rolls back the request, but the audit entry has its own transaction."""
    client.post("/api/auth/login", json={"email": "nobody@test.local", "password": "x"},
                headers={"X-CSRF-Token": csrf(client)})
    assert events(app)[-1].event == "login_failed"


def test_before_and_after_values_are_kept(app):
    with app.app_context():
        audit.record("address_changed", 7, before={"address": "1 Old St"}, after={"address": "2 New St"})
        e = AuditEvent.query.one()
        assert "1 Old St" in e.details and "2 New St" in e.details and e.actor_id == 7


def test_voter_events_store_date_only_and_no_ip(app, client):
    login(client, "voter1@test.local", "pw-voter")
    e = events(app)[-1]
    assert e.event == "login_ok" and len(e.occurred_at) == 10 and e.source_ip is None


def test_staff_events_store_full_time_and_ip(app, client):
    login(client, "tally@test.local", "pw-tally")
    e = events(app)[-1]
    assert "T" in e.occurred_at and e.source_ip is not None


def test_clean_chain_verifies(app):
    with app.app_context():
        for i in range(5):
            audit.record("test_event", i)
        result = audit.verify()
        assert result["ok"] and result["checked"] == 5


def test_database_blocks_update_and_delete(app):
    with app.app_context():
        audit.record("test_event", 1)
        with pytest.raises(DatabaseError, match="append-only"):
            db.session.execute(text("UPDATE audit_events SET event='x'"), bind_arguments={"bind": db.engines["audit"]})
        db.session.rollback()
        with pytest.raises(DatabaseError, match="append-only"):
            db.session.execute(text("DELETE FROM audit_events"), bind_arguments={"bind": db.engines["audit"]})
        db.session.rollback()


def _drop_triggers(app):
    """Simulates an attacker with full DB admin rights removing the triggers."""
    eng = db.engines["audit"]
    with eng.begin() as c:
        c.execute(text("DROP TRIGGER audit_no_update"))
        c.execute(text("DROP TRIGGER audit_no_delete"))


def test_modified_entry_is_detected_even_without_triggers(app):
    with app.app_context():
        for i in range(3):
            audit.record("test_event", i)
        _drop_triggers(app)
        with db.engines["audit"].begin() as c:
            c.execute(text("UPDATE audit_events SET actor_id=999 WHERE seq=2"))
        result = audit.verify()
        assert not result["ok"] and any(p["seq"] == 2 and "modified" in p["reason"] for p in result["problems"])


def test_deleted_entries_are_detected(app):
    with app.app_context():
        for i in range(3):
            audit.record("test_event", i)
        _drop_triggers(app)
        with db.engines["audit"].begin() as c:
            c.execute(text("DELETE FROM audit_events WHERE seq=3"))
        assert not audit.verify()["ok"]


def test_audit_api_is_auditor_only(app, client, auditor):
    assert client.get("/api/audit/events").status_code == 401
    login(client, "tally@test.local", "pw-tally")
    assert client.get("/api/audit/events").status_code == 403
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    login(client, "auditor@test.local", "pw-audit")
    r = client.get("/api/audit/verify").get_json()
    assert r["ok"] is True
    assert any(e["event"] == "access_denied" for e in client.get("/api/audit/events").get_json()["events"])


def test_no_api_to_change_the_log(app, client, auditor):
    login(client, "auditor@test.local", "pw-audit")
    c = csrf(client)
    for method in ("post", "put", "delete"):
        assert getattr(client, method)("/api/audit/events", headers={"X-CSRF-Token": c}).status_code == 405
