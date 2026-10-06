"""SR-04: tamper-evident, append-only audit log.

Every entry is chained to the one before it:
    entry_hash = HMAC-SHA256(audit_key, prev_hash + canonical JSON of the entry)
Changing, deleting, inserting or reordering any entry breaks the chain, and
without the audit key the chain can't be rebuilt. On top of that, the
database has triggers that reject UPDATE and DELETE on the table.

Entries are written in their own transaction, so an event is still recorded
when the request that caused it fails (e.g. a rejected login).

Never pass ballot contents, ballot tokens or passwords here.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone

from flask import current_app, has_request_context, request
from sqlalchemy.orm import Session

from .extensions import db
from .models import AuditEvent, AuditHead

GENESIS = "0" * 64


def _canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _entry_hash(key, prev_hash, entry):
    return hmac.new(key, (prev_hash + _canonical(entry)).encode(), hashlib.sha256).hexdigest()


def _fields(e):
    return {"seq": e.seq, "occurred_at": e.occurred_at, "actor_id": e.actor_id,
            "event": e.event, "source_ip": e.source_ip, "details": e.details}


def record(event, actor=None, *, coarse_time=False, **details):
    """Append one audit entry.

    coarse_time=True stores the date only and no IP. Used for voter events,
    where an exact time could be matched against ballot order (SR-14).
    """
    now = datetime.now(timezone.utc)
    entry = {
        "event": event,
        "actor_id": actor,
        "occurred_at": now.date().isoformat() if coarse_time else now.isoformat(timespec="seconds"),
        "source_ip": None if coarse_time or not has_request_context() else request.remote_addr,
        "details": _canonical(details),
    }
    key = current_app.extensions["keys"].audit_key()
    with Session(db.engines["audit"]) as s, s.begin():
        head = s.get(AuditHead, 1, with_for_update=True)
        if head is None:
            head = AuditHead(id=1, last_seq=0, last_hash=GENESIS)
            s.add(head)
        entry["seq"] = head.last_seq + 1
        h = _entry_hash(key, head.last_hash, entry)
        s.add(AuditEvent(**entry, prev_hash=head.last_hash, entry_hash=h))
        head.last_seq, head.last_hash = entry["seq"], h


def verify():
    """Walk the whole chain. Returns a dict the auditor screen can show."""
    key = current_app.extensions["keys"].audit_key()
    rows = db.session.query(AuditEvent).order_by(AuditEvent.seq).all()
    problems, prev, expected = [], GENESIS, 1
    for e in rows:
        if e.seq != expected:
            problems.append({"seq": e.seq, "reason": f"sequence gap, expected {expected}"})
        if e.prev_hash != prev:
            problems.append({"seq": e.seq, "reason": "does not link to previous entry"})
        if not hmac.compare_digest(_entry_hash(key, e.prev_hash, _fields(e)), e.entry_hash):
            problems.append({"seq": e.seq, "reason": "entry was modified"})
        prev, expected = e.entry_hash, e.seq + 1
    head = db.session.get(AuditHead, 1)
    if head is not None and (head.last_seq != len(rows) or head.last_hash != prev):
        problems.append({"seq": None, "reason": "log was truncated or entries removed"})
    return {"ok": not problems, "checked": len(rows), "problems": problems}
