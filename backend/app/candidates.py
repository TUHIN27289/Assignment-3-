"""SR-17: dual control for candidate data.

No single delegate can change the ballot on their own. Every change is
proposed by one delegate and only takes effect once a DIFFERENT delegate
for the same state approves it:
  - create a candidate
  - update name, party or ballot order
  - exclude a candidate (manual exclusion for a recount ordered by the
    Court of Disputed Returns), with a written reason

Other rules:
  - a delegate can only act for their own state
  - requests expire after 24 hours
  - create/update are frozen once any ballot has been cast; only exclusions
    are allowed after that (a recount happens after voting)
  - approval is a conditional UPDATE on status = 'pending', so the same
    request can't be applied twice even if two approvals arrive together
  - request, approval and rejection are all audited with before/after values
"""
import json
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, g, jsonify, request
from sqlalchemy import update

from . import audit
from .auth import permission_required
from .extensions import db
from .models import Candidate, CastBallot, PendingChange

bp = Blueprint("candidates", __name__, url_prefix="/api/candidates")

EXPIRY = timedelta(hours=24)
EDITABLE = {"name": str, "party": str, "ballot_order": int, "division": str}
MAX_TEXT = 255


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _delegate_state():
    if not g.user.state:
        abort(403, description="delegate has no state assigned")
    return g.user.state


def _as_dict(c):
    return {"id": c.id, "name": c.name, "party": c.party, "division": c.division,
            "ballot_order": c.ballot_order, "excluded": c.excluded, "exclusion_reason": c.exclusion_reason}


def _clean_fields(data, required):
    fields = data.get("fields") or {}
    if not isinstance(fields, dict) or set(fields) - set(EDITABLE):
        abort(400, description=f"fields may only contain {sorted(EDITABLE)}")
    for k, v in fields.items():
        if type(v) is not EDITABLE[k]:
            abort(400, description=f"{k} has the wrong type")
        if isinstance(v, str) and not 0 < len(v.strip()) <= MAX_TEXT:
            abort(400, description=f"{k} must be 1 to {MAX_TEXT} characters")
        if k == "ballot_order" and not 1 <= v <= 100:
            abort(400, description="ballot_order must be 1 to 100")
    if required - set(fields):
        abort(400, description=f"missing {sorted(required - set(fields))}")
    return {k: v.strip() if isinstance(v, str) else v for k, v in fields.items()}


def _voting_started():
    return db.session.query(CastBallot.seq).first() is not None


def _view(p):
    return {"id": p.id, "kind": p.kind, "candidate_id": p.candidate_id, "payload": json.loads(p.payload),
            "reason": p.reason, "requested_by": p.requested_by, "status": p.status,
            "requested_at": p.requested_at.isoformat(timespec="seconds"),
            "expires_at": (p.requested_at + EXPIRY).isoformat(timespec="seconds"),
            "mine": p.requested_by == g.user.id}


@bp.get("")
@permission_required("candidates:read")
def list_candidates():
    state = _delegate_state()
    rows = Candidate.query.filter_by(state=state).order_by(Candidate.division, Candidate.ballot_order)
    pending = PendingChange.query.filter_by(state=state, status="pending").order_by(PendingChange.id)
    return jsonify(state=state, candidates=[_as_dict(c) for c in rows],
                   pending=[_view(p) for p in pending if not _expire_if_old(p)])


def _expire_if_old(p):
    if p.status == "pending" and _now() - p.requested_at > EXPIRY:
        p.status = "expired"
        db.session.commit()
        return True
    return False


@bp.post("/changes")
@permission_required("candidates:write")
def request_change():
    state = _delegate_state()
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    reason = data.get("reason")
    if kind not in ("create", "update", "exclude"):
        abort(400, description="kind must be create, update or exclude")
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
        abort(400, description="a reason of 10 to 500 characters is required")

    candidate = None
    if kind in ("update", "exclude"):
        candidate = db.session.get(Candidate, data.get("candidate_id")) if type(data.get("candidate_id")) is int else None
        if candidate is None or candidate.state != state:
            abort(404, description="no such candidate in your state")
    if kind in ("create", "update") and _voting_started():
        abort(409, description="candidate details are frozen once voting has started")
    if kind == "exclude" and candidate.excluded:
        abort(409, description="candidate already excluded")

    if kind == "create":
        payload = _clean_fields(data, required={"name", "division", "ballot_order"})
    elif kind == "update":
        payload = _clean_fields(data, required=set())
        if not payload:
            abort(400, description="nothing to change")
    else:
        payload = {}

    p = PendingChange(kind=kind, candidate_id=candidate.id if candidate else None, state=state,
                      payload=json.dumps(payload), reason=reason.strip(), requested_by=g.user.id,
                      requested_at=_now())
    db.session.add(p)
    db.session.commit()
    audit.record("candidate_change_requested", g.user.id, change_id=p.id, kind=kind,
                 candidate_id=p.candidate_id, requested=payload, reason=p.reason)
    return jsonify(_view(p)), 201


def _decide(change_id, approve):
    state = _delegate_state()
    p = db.session.get(PendingChange, change_id)
    if p is None or p.state != state:
        abort(404)
    if _expire_if_old(p) or p.status != "pending":
        abort(409, description=f"request is {p.status}")
    if p.requested_by == g.user.id:
        audit.record("dual_control_violation", g.user.id, change_id=p.id)
        abort(403, description="a second delegate must approve this, not the requester")

    # Claim the request atomically so it can only be decided once
    claimed = db.session.execute(
        update(PendingChange).where(PendingChange.id == p.id, PendingChange.status == "pending")
        .values(status="applied" if approve else "rejected", decided_by=g.user.id, decided_at=_now())
    ).rowcount
    if claimed != 1:
        db.session.rollback()
        abort(409, description="request was already decided")
    if not approve:
        db.session.commit()
        audit.record("candidate_change_rejected", g.user.id, change_id=p.id)
        return jsonify(status="rejected")

    payload = json.loads(p.payload)
    before = None
    if p.kind == "create":
        if _voting_started():
            db.session.rollback()
            abort(409, description="candidate details are frozen once voting has started")
        c = Candidate(state=p.state, **payload)
        db.session.add(c)
        db.session.flush()
    else:
        c = db.session.get(Candidate, p.candidate_id)
        before = _as_dict(c)
        if p.kind == "update":
            if _voting_started():
                db.session.rollback()
                abort(409, description="candidate details are frozen once voting has started")
            for k, v in payload.items():
                setattr(c, k, v)
        else:
            c.excluded = True
            c.exclusion_reason = p.reason
    db.session.commit()
    audit.record("candidate_change_applied", g.user.id, change_id=p.id, kind=p.kind,
                 requested_by=p.requested_by, before=before, after=_as_dict(c))
    return jsonify(status="applied", candidate=_as_dict(c))


@bp.post("/changes/<int:change_id>/approve")
@permission_required("candidates:write")
def approve(change_id):
    return _decide(change_id, True)


@bp.post("/changes/<int:change_id>/reject")
@permission_required("candidates:write")
def reject(change_id):
    return _decide(change_id, False)
