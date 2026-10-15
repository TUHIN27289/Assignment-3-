"""Tally: counts the ballots that pass every integrity check.

reconcile() (SR-19) and verify_chain() (SR-15) both run before anything
is counted.
Only ballots that pass are decrypted (SR-13, private key used here only).
Nothing is decrypted or counted before polls close (ELECTION_CLOSES_AT), so
no one, not even a tally officer, can see early trends while people are
still voting. Reconciliation (counts of records only) can run at any time.
Candidates excluded through dual control (SR-17) are skipped, and each
ballot counts for that voter's next preference instead.
Counting is first preferences only. Full preferential counting (seats
decided over several rounds) is out of scope for the prototype.
"""
from collections import Counter

from flask import Blueprint, abort, current_app, g, jsonify

from .. import audit
from ..auth import permission_required
from ..ballot.crypto import (GENESIS_MAC, EncryptedBallot, ballot_digest,
                             chain_mac, decrypt_ballot)
from ..extensions import db
from ..models import Candidate, CastBallot, ChainHead, IntegrityAlert
from ..results import VotingStillOpen, create_package, voting_closed
from .reconcile import reconcile

bp = Blueprint("tally", __name__, url_prefix="/api/tally")


def verify_chain(integrity_key):
    """Returns (valid_ballots, problems). problems is a list of (seq, reason)."""
    ballots = CastBallot.query.order_by(CastBallot.seq).all()
    valid, problems = [], []
    prev_mac = GENESIS_MAC
    expected_seq = 1

    for b in ballots:
        if b.seq != expected_seq:
            problems.append((b.seq, f"sequence gap, expected {expected_seq}"))
        expected_seq = b.seq + 1

        enc = EncryptedBallot(b.ciphertext, b.nonce, b.wrapped_key)
        digest_ok = ballot_digest(b.ballot_id, b.election_id, b.division, enc) == b.digest
        mac_ok = chain_mac(integrity_key, prev_mac, b.digest) == b.chain_mac
        if not digest_ok:
            problems.append((b.seq, "ballot contents do not match digest"))
        if not mac_ok:
            problems.append((b.seq, "hash chain broken"))
        if digest_ok and mac_ok:
            valid.append(b)
        # carry on from the stored mac so one bad row doesn't hide later ones
        prev_mac = b.chain_mac

    head = db.session.get(ChainHead, 1)
    if head is not None and (head.last_seq != len(ballots) or head.last_mac != prev_mac):
        problems.append((None, "chain head does not match stored ballots (deleted or appended rows)"))
    return valid, problems


def run_tally():
    closed, reason = voting_closed()
    if not closed:
        raise VotingStillOpen(reason)  # checked before any ballot is decrypted
    keys = current_app.extensions["keys"]
    reconciliation = reconcile()  # SR-19, before anything is decrypted
    valid, problems = verify_chain(keys.integrity_key())
    for seq, reason in problems:
        db.session.add(IntegrityAlert(seq=seq, reason=reason))
    db.session.commit()

    private_key = keys.ballot_private_key()
    # SR-17: a candidate excluded by approved court order is skipped, and the
    # ballot counts for that voter's next preference instead
    excluded = {c.id for c in Candidate.query.filter_by(excluded=True)}
    first_prefs = Counter()
    exhausted = 0  # every preference on the ballot was excluded, so it counts for nobody
    for b in valid:
        ballot = decrypt_ballot(EncryptedBallot(b.ciphertext, b.nonce, b.wrapped_key),
                                private_key, b.ballot_id)
        choice = next((c for c in ballot["house"] if c not in excluded), None)
        if choice is not None:
            first_prefs[(b.division, choice)] += 1
        else:
            exhausted += 1

    # Every candidate still in the count is listed, 0 votes included, so a
    # published result can't quietly leave anyone out
    candidates = Candidate.query.all()
    names = {c.id: c.name for c in candidates}
    results = {}
    for c in candidates:
        if c.id not in excluded:
            results.setdefault(c.division, {})[c.name] = 0
    for (division, candidate_id), n in first_prefs.items():
        results.setdefault(division, {})[names.get(candidate_id, str(candidate_id))] = n
    return {
        "counted": len(valid),
        "reconciliation": reconciliation,
        "rejected": [{"seq": s, "reason": r} for s, r in problems],
        "first_preferences": results,
        "exhausted": exhausted,  # candidate totals + exhausted == counted
        "excluded": sorted(names.get(i, str(i)) for i in excluded),
    }


@bp.post("/run")
@permission_required("tally:run")
def run():
    try:
        result = run_tally()
    except VotingStillOpen as e:
        audit.record("tally_refused_voting_open", g.user.id, reason=str(e))
        abort(409, description=f"Counting starts after polls close: {e}")
    # SR-18/SR-19: after polls close, a failed reconciliation still shows the
    # officer the numbers to investigate, but nothing is signed or published
    reason = None if result["reconciliation"]["ok"] else "reconciliation failed"
    if reason:
        result["signed_package"] = None
        result["publication_blocked"] = reason
        audit.record("results_publication_blocked", g.user.id, counted=result["counted"], reason=reason,
                     problems=result["reconciliation"]["problems"])
        return jsonify(result)
    result["signed_package"] = create_package(result)  # SR-18
    audit.record("tally_run", g.user.id, counted=result["counted"],
                 rejected=len(result["rejected"]), results_sha256=result["signed_package"]["sha256"],
                 kid=result["signed_package"]["kid"])
    return jsonify(result)


@bp.post("/reconcile")  # POST: it records alerts and an audit entry, so it needs CSRF protection
@permission_required("tally:reconcile")
def reconcile_endpoint():
    result = reconcile()
    audit.record("reconciliation_run", g.user.id, ok=result["ok"])
    return jsonify(result)
