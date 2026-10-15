"""SR-18: signed results export.

Each tally run produces a results package that external systems (media,
parliament, the Court of Disputed Returns) can trust without trusting the
network in between:
  - aggregates only: per-division totals per candidate. No ballot ids,
    digests, ciphertexts or anything at ballot level (no booth-level
    breakdown either, so small groups of voters can't be singled out)
  - canonical JSON, signed with the current Ed25519 results key (SR-20),
    with the key id (kid) inside the response so it still verifies after
    a key rotation
  - generated_at timestamp and a sequence number inside the signed data,
    so an old package can't be passed off as the latest recount
  - nothing is signed if reconciliation failed (SR-19): the AEC doesn't vouch
    for numbers that don't add up. The reconciliation result is also signed
    into the package, so this can be checked by anyone
  - every candidate still in the count is listed, 0 votes included, and
    excluded candidates are listed separately. Ballots whose preferences were
    all excluded are signed in as exhausted_ballots, so the totals add up to
    ballots_counted

Anyone can fetch and verify packages. Only the tally creates them. The
public verify endpoint is rate limited per IP and refuses oversized bodies,
so it can't be used to flood the server with expensive signature checks.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, abort, current_app, jsonify, request

from .extensions import db, limiter
from .models import ResultsPackage
from .security.rbac import public

bp = Blueprint("results", __name__, url_prefix="/api/results")

MAX_VERIFY_BYTES = 256 * 1024  # a real package for every division is well under this


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class ReconciliationFailed(RuntimeError):
    pass


def create_package(tally_result):
    """Build, sign and store a results package from a run_tally() result."""
    if not tally_result["reconciliation"]["ok"]:
        raise ReconciliationFailed("results are not signed while reconciliation fails")
    last = db.session.query(db.func.max(ResultsPackage.seq)).scalar() or 0
    payload = {
        "v": 1,
        "election_id": current_app.config["ELECTION_ID"],
        "sequence": last + 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": "house-first-preferences",
        "ballots_counted": tally_result["counted"],
        "ballots_rejected": len(tally_result["rejected"]),
        "exhausted_ballots": tally_result["exhausted"],
        "reconciliation_ok": tally_result["reconciliation"]["ok"],
        "excluded_candidates": tally_result["excluded"],
        "divisions": tally_result["first_preferences"],
    }
    kid, key = current_app.extensions["keys"].signing_key("results")
    sig = base64.urlsafe_b64encode(key.sign(_canonical(payload))).decode()
    db.session.add(ResultsPackage(seq=payload["sequence"], payload=_canonical(payload).decode(),
                                  kid=kid, signature=sig))
    db.session.commit()
    return _export(payload, kid, sig)


def _export(payload, kid, sig):
    return {"package": payload, "kid": kid, "signature": sig, "algorithm": "Ed25519",
            "sha256": hashlib.sha256(_canonical(payload)).hexdigest()}


def verify_package(payload, kid, signature):
    pem = current_app.extensions["keys"].public_keys("results").get(kid)
    if pem is None:
        return False
    try:
        serialization.load_pem_public_key(pem.encode()).verify(
            base64.urlsafe_b64decode(signature), _canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _load(row):
    return _export(json.loads(row.payload), row.kid, row.signature)


@bp.get("/latest")
@public
def latest():
    row = ResultsPackage.query.order_by(ResultsPackage.seq.desc()).first()
    if row is None:
        abort(404, description="no results published yet")
    return jsonify(_load(row))


@bp.get("/<int:seq>")
@public
def by_sequence(seq):
    row = db.session.get(ResultsPackage, seq)
    if row is None:
        abort(404)
    return jsonify(_load(row))


@bp.post("/verify")
@public
@limiter.limit("30 per minute")
def verify():
    if request.content_length is None or request.content_length > MAX_VERIFY_BYTES:
        abort(413, description=f"package must be sent with a size of at most {MAX_VERIFY_BYTES} bytes")
    data = request.get_json(silent=True) or {}
    payload, kid, sig = data.get("package"), data.get("kid"), data.get("signature")
    if not isinstance(payload, dict) or not isinstance(kid, str) or not isinstance(sig, str) or len(sig) > 200:
        abort(400, description="expected package, kid and signature")
    return jsonify(valid=verify_package(payload, kid, sig))
