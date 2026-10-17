"""Ballot casting.

Two steps, so the identity side and the ballot side never meet (SR-14):

1. POST /api/ballot/token  (logged-in voter)
   Checks eligibility, marks the voter as issued (a flag, no time), and
   returns a random one-time token. Only the token's SHA-256 hash is stored,
   in the ballot database, with no voter id. The server keeps no record of
   which voter got which token.

2. POST /api/ballot/cast  (anonymous, token only)
   Deliberately never looks at the session. The ballot is validated,
   encrypted (SR-13), appended to the hash chain (SR-15) and the token is
   burned. No timestamp, voter id or IP is written with the ballot.
"""
import hashlib
import secrets
import uuid

from flask import Blueprint, abort, current_app, g, jsonify, request
from sqlalchemy import update

from ..auth import permission_required
from ..security.rbac import public
from ..extensions import db
from ..models import BallotToken, Candidate, CastBallot, ChainHead, Voter
from .crypto import GENESIS_MAC, ballot_digest, chain_mac, encrypt_ballot, sign_receipt, verify_receipt
from .validation import InvalidBallot, validate_ballot
from ..ip_validator import DiplomaticIPValidator

bp = Blueprint("ballot", __name__, url_prefix="/api/ballot")


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@bp.get("/candidates")
@permission_required("ballot:vote")
def candidates():
    voter = Voter.query.filter_by(user_id=g.user.id).first()
    if voter is None:
        abort(403)
    rows = Candidate.query.filter_by(division=voter.division).order_by(Candidate.ballot_order)
    return jsonify(division=voter.division, issued=voter.ballot_issued,
                   candidates=[{"id": c.id, "name": c.name, "party": c.party} for c in rows])


@bp.post("/token")
@permission_required("ballot:vote")
def issue_token():
    if request.headers.get("X-Overseas-Voting") == "true" or request.args.get("overseas") == "true":
        ranges = current_app.config.get("DIPLOMATIC_MISSION_IP_RANGES", "")
        client_ip = DiplomaticIPValidator.extract_client_ip(request)
        if not DiplomaticIPValidator.is_ip_allowed(client_ip, ranges):
            abort(403, description="access restricted to authorized diplomatic mission networks")

    voter = Voter.query.filter_by(user_id=g.user.id).first()
    if voter is None or not voter.enrolled:
        abort(403, description="not enrolled")

    # Atomic claim: only succeeds if no ballot was issued yet (base for SR-09)
    claimed = db.session.execute(
        update(Voter)
        .where(Voter.id == voter.id, Voter.enrolled.is_(True), Voter.ballot_issued.is_(False))
        .values(ballot_issued=True)
    ).rowcount
    if claimed != 1:
        db.session.rollback()
        abort(409, description="ballot already issued")

    token = secrets.token_urlsafe(32)
    db.session.add(BallotToken(token_hash=_hash_token(token), division=voter.division))
    db.session.commit()
    # Deliberately not audited: a timestamped "voter X got a token" entry could be
    # lined up with the order of ballots in the chain (SR-14). The voter's
    # ballot_issued flag is the record that a ballot was issued.
    return jsonify(ballot_token=token, division=voter.division)


@bp.post("/overseas/token")
@permission_required("ballot:vote")
def issue_overseas_token():
    ranges = current_app.config.get("DIPLOMATIC_MISSION_IP_RANGES", "")
    client_ip = DiplomaticIPValidator.extract_client_ip(request)
    if not DiplomaticIPValidator.is_ip_allowed(client_ip, ranges):
        abort(403, description="access restricted to authorized diplomatic mission networks")
    return issue_token()


def append_ballot(ballot, division):
    """Encrypt a validated ballot and append it to the chain. Caller commits."""
    keys = current_app.extensions["keys"]
    election_id = current_app.config["ELECTION_ID"]
    ballot_id = str(uuid.uuid4())

    enc = encrypt_ballot(ballot, keys.ballot_public_key(), ballot_id)
    digest = ballot_digest(ballot_id, election_id, division, enc)

    head = db.session.get(ChainHead, 1, with_for_update=True)
    if head is None:
        head = ChainHead(id=1, last_seq=0, last_mac=GENESIS_MAC)
        db.session.add(head)
    mac = chain_mac(keys.integrity_key(), head.last_mac, digest)

    db.session.add(CastBallot(
        seq=head.last_seq + 1, ballot_id=ballot_id, election_id=election_id,
        division=division, ciphertext=enc.ciphertext, nonce=enc.nonce,
        wrapped_key=enc.wrapped_key, digest=digest, chain_mac=mac,
    ))
    head.last_seq += 1
    head.last_mac = mac
    return digest


@bp.post("/cast")
@public  # anonymous on purpose (SR-14), the one-time token is the credential
def cast():
    if request.headers.get("X-Overseas-Voting") == "true" or request.args.get("overseas") == "true":
        ranges = current_app.config.get("DIPLOMATIC_MISSION_IP_RANGES", "")
        client_ip = DiplomaticIPValidator.extract_client_ip(request)
        if not DiplomaticIPValidator.is_ip_allowed(client_ip, ranges):
            abort(403, description="access restricted to authorized diplomatic mission networks")

    data = request.get_json(silent=True) or {}
    token = data.get("ballot_token")
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        abort(400, description="missing ballot token")

    token_hash = _hash_token(token)
    # Burn the token in one conditional UPDATE. Reading it first and marking it
    # used later would let two simultaneous requests with the same token both
    # pass the check and store two ballots.
    burned = db.session.execute(
        update(BallotToken)
        .where(BallotToken.token_hash == token_hash, BallotToken.used.is_(False))
        .values(used=True)
    ).rowcount
    if burned != 1:
        db.session.rollback()
        abort(403, description="invalid or used ballot token")
    division = db.session.get(BallotToken, token_hash).division

    try:
        ballot = validate_ballot(data.get("ballot"), division)
    except InvalidBallot as e:
        db.session.rollback()  # token stays usable so the voter can fix the ballot
        abort(400, description=str(e))

    digest = append_ballot(ballot, division)
    db.session.commit()
    # SR-10: signed voter receipt with tracking code
    keys = current_app.extensions["keys"]
    receipt_sig = sign_receipt(keys.receipt_key(), digest)
    return jsonify(tracking_code=digest, receipt=receipt_sig, signature=receipt_sig)


@bp.post("/receipt/verify")
@public
def verify_receipt_endpoint():
    data = request.get_json(silent=True) or {}
    tracking_code = data.get("tracking_code")
    signature = data.get("signature") or data.get("receipt")
    if not tracking_code or not signature:
        abort(400, description="missing tracking_code or signature")
    keys = current_app.extensions["keys"]
    valid = verify_receipt(keys.receipt_key(), tracking_code, signature)
    return jsonify(valid=valid, tracking_code=tracking_code)
