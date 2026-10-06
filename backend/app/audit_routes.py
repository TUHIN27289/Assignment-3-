"""SR-04: read-only audit API for the auditor role. There is no endpoint that
changes or deletes entries."""
import json

from flask import Blueprint, g, jsonify

from . import audit
from .auth import permission_required
from .extensions import db
from .models import AuditEvent, User

bp = Blueprint("audit", __name__, url_prefix="/api/audit")


@bp.get("/events")
@permission_required("audit:read")
def events():
    rows = db.session.query(AuditEvent).order_by(AuditEvent.seq.desc()).limit(200).all()
    ids = {r.actor_id for r in rows if r.actor_id}
    emails = {u.id: u.email for u in User.query.filter(User.id.in_(ids))}
    audit.record("audit_viewed", g.user.id)
    return jsonify(events=[{
        "seq": r.seq, "occurred_at": r.occurred_at, "event": r.event,
        "actor": emails.get(r.actor_id), "source_ip": r.source_ip,
        "details": json.loads(r.details),
    } for r in rows])


@bp.get("/verify")
@permission_required("audit:read")
def verify():
    result = audit.verify()
    audit.record("audit_verified", g.user.id, ok=result["ok"], checked=result["checked"])
    return jsonify(result)
