"""SR-02: role-based access control, least privilege, deny by default."""
import pytest

from app.auth import hash_password
from app.extensions import db
from app.models import User
from app.security.rbac import PERMISSIONS

from .conftest import csrf, login

ROLES = ["voter", "enrolment_officer", "delegate", "tally_officer", "auditor"]

# (method, path, permission it needs)
PROTECTED = [
    ("get", "/api/ballot/candidates", "ballot:vote"),
    ("post", "/api/ballot/token", "ballot:vote"),
    ("post", "/api/tally/run", "tally:run"),
    ("get", "/api/audit/events", "audit:read"),
    ("get", "/api/audit/verify", "audit:read"),
]


@pytest.fixture
def staff(app):
    with app.app_context():
        for role in ["enrolment_officer", "delegate", "auditor"]:
            db.session.add(User(email=f"{role}@test.local", password_hash=hash_password("pw"), role=role))
        db.session.commit()


def login_as(client, role):
    emails = {"voter": ("voter1@test.local", "pw-voter"), "tally_officer": ("tally@test.local", "pw-tally")}
    email, pw = emails.get(role, (f"{role}@test.local", "pw"))
    return login(client, email, pw)


@pytest.mark.parametrize("role", ROLES)
def test_access_matrix(app, staff, role):
    client = app.test_client()
    c = login_as(client, role)
    for method, path, permission in PROTECTED:
        r = getattr(client, method)(path, headers={"X-CSRF-Token": c})
        if permission in PERMISSIONS[role]:
            assert r.status_code not in (401, 403), (role, path)
        else:
            assert r.status_code == 403, (role, path)


def test_every_protected_route_needs_login(client):
    c = csrf(client)
    for method, path, _ in PROTECTED:
        assert getattr(client, method)(path, headers={"X-CSRF-Token": c}).status_code == 401


def test_least_privilege_no_role_has_everything():
    everything = set().union(*PERMISSIONS.values())
    for role, perms in PERMISSIONS.items():
        assert perms != everything, role
    # nobody who counts votes can also cast them or read the audit trail about themselves
    assert not {"ballot:vote", "audit:read"} & PERMISSIONS["tally_officer"]


def test_route_without_access_rule_is_denied(app, client):
    app.add_url_rule("/api/forgotten", "forgotten", lambda: "should not be reachable")
    assert client.get("/api/forgotten").status_code == 403


def test_role_change_takes_effect_immediately(app, client):
    """Role is read from the DB each request, not remembered in the session."""
    c = login(client, "tally@test.local", "pw-tally")
    assert client.post("/api/tally/run", headers={"X-CSRF-Token": c}).status_code == 200
    with app.app_context():
        User.query.filter_by(email="tally@test.local").one().role = "voter"
        db.session.commit()
    assert client.post("/api/tally/run", headers={"X-CSRF-Token": c}).status_code == 403


def test_denied_access_is_audited(app, client):
    from app.models import AuditEvent
    c = login(client, "voter1@test.local", "pw-voter")
    client.post("/api/tally/run", headers={"X-CSRF-Token": c})
    with app.app_context():
        e = AuditEvent.query.order_by(AuditEvent.seq.desc()).first()
        assert e.event == "access_denied" and "tally:run" in e.details
