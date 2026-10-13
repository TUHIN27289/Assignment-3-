"""SR-07: two-person approval for bulk export of elector records.

Exporting the roll is the quickest way to leak a lot of personal data at
once, so:
  - exports up to EXPORT_APPROVAL_THRESHOLD records (500) can be approved by
    the requester's own request, still audited
  - bigger exports need a SECOND enrolment officer to approve; the
    requester can never approve their own
  - requests expire after 24 hours
  - each approved export can be downloaded ONCE, only by the requester
  - if the roll grew past what was approved, the download is refused
  - a written reason is required, and every step is audited (count and
    who approved, never the personal data itself)
  - requesting and approving need a recent password (SR-06)
  - CSV cells are escaped against spreadsheet formula injection
"""
import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, current_app, g, jsonify, request
from sqlalchemy import update

from . import audit
from .auth import role_required
from .auth.sessions import recent_auth_required
from .extensions import db
from .models import ExportRequest, User, Voter

bp = Blueprint("exports", __name__, url_prefix="/api/enrolment/exports")
EXPIRY = timedelta(hours=24)
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _query(division):
    q = db.session.query(Voter, User.email).join(User, User.id == Voter.user_id)
    return q.filter(Voter.division == division) if division else q


def _view(r):
    return {"id": r.id, "division": r.division, "record_count": r.record_count, "reason": r.reason,
            "status": r.status, "requested_at": r.requested_at.isoformat(timespec="seconds"),
            "mine": r.requested_by == g.user.id}


def _expire(r):
    if r.status in ("pending", "approved") and _now() - r.requested_at > EXPIRY:
        r.status = "expired"
        db.session.commit()
    return r


@bp.post("")
@role_required("enrolment_officer")
@recent_auth_required
def request_export():
    data = request.get_json(silent=True) or {}
    division = data.get("division") or None
    reason = data.get("reason")
    if division is not None and (not isinstance(division, str) or len(division) > 64):
        abort(400, description="division is not valid")
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
        abort(400, description="a reason of 10 to 500 characters is required")
    count = _query(division).count()
    small = count <= current_app.config["EXPORT_APPROVAL_THRESHOLD"]
    r = ExportRequest(requested_by=g.user.id, division=division, record_count=count, reason=reason.strip(),
                      requested_at=_now(), status="approved" if small else "pending",
                      approved_by=g.user.id if small else None, decided_at=_now() if small else None)
    db.session.add(r)
    db.session.commit()
    audit.record("export_requested", g.user.id, export_id=r.id, records=count, division=division,
                 needs_approval=not small)
    return jsonify(_view(r)), 201


@bp.get("")
@role_required("enrolment_officer")
def list_requests():
    rows = ExportRequest.query.order_by(ExportRequest.id.desc()).limit(50).all()
    return jsonify(requests=[_view(_expire(r)) for r in rows])


def _decide(export_id, approve):
    r = db.session.get(ExportRequest, export_id)
    if r is None:
        abort(404)
    if _expire(r).status != "pending":
        abort(409, description=f"request is {r.status}")
    if r.requested_by == g.user.id:
        audit.record("dual_control_violation", g.user.id, export_id=r.id)
        abort(403, description="a second enrolment officer must approve this export")
    done = db.session.execute(update(ExportRequest)
                              .where(ExportRequest.id == r.id, ExportRequest.status == "pending")
                              .values(status="approved" if approve else "rejected",
                                      approved_by=g.user.id if approve else None, decided_at=_now())).rowcount
    db.session.commit()
    if done != 1:
        abort(409, description="request was already decided")
    audit.record("export_approved" if approve else "export_rejected", g.user.id, export_id=r.id,
                 requested_by=r.requested_by, records=r.record_count)
    return jsonify(status="approved" if approve else "rejected")


@bp.post("/<int:export_id>/approve")
@role_required("enrolment_officer")
@recent_auth_required
def approve(export_id):
    return _decide(export_id, True)


@bp.post("/<int:export_id>/reject")
@role_required("enrolment_officer")
def reject(export_id):
    return _decide(export_id, False)


def _cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


@bp.get("/<int:export_id>/download")
@role_required("enrolment_officer")
def download(export_id):
    r = db.session.get(ExportRequest, export_id)
    if r is None or r.requested_by != g.user.id:
        abort(404)
    if _expire(r).status != "approved":
        abort(409, description=f"export is {r.status}")
    rows = _query(r.division).order_by(Voter.id).all()
    if len(rows) > max(r.record_count, current_app.config["EXPORT_APPROVAL_THRESHOLD"]):
        abort(409, description="the roll changed since approval, request the export again")
    # one download only: flip approved -> downloaded atomically
    done = db.session.execute(update(ExportRequest)
                              .where(ExportRequest.id == r.id, ExportRequest.status == "approved")
                              .values(status="downloaded", downloaded_at=_now())).rowcount
    db.session.commit()
    if done != 1:
        abort(409, description="export was already downloaded")

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "full_name", "date_of_birth", "address", "division", "email", "enrolled"])
    for v, email in rows:
        w.writerow([_cell(x) for x in (v.id, v.full_name, v.date_of_birth, v.address, v.division, email, v.enrolled)])
    audit.record("pii_export", g.user.id, export_id=r.id, records=len(rows), approved_by=r.approved_by)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="roll-export-{r.id}.csv"'})
