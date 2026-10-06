"""SR-15: per-ballot digest + keyed hash chain, verified before counting."""
import uuid

from app.ballot.crypto import encrypt_ballot, ballot_digest, chain_mac
from app.extensions import db
from app.models import CastBallot, IntegrityAlert
from app.tally import run_tally, verify_chain

from .conftest import vote

EMAILS = ["voter1@test.local", "voter2@test.local", "voter3@test.local"]


def cast_three(app, client):
    for e in EMAILS:
        assert vote(app, app.test_client(), e).status_code == 200


def verify(app):
    return verify_chain(app.extensions["keys"].integrity_key())


def test_clean_chain_verifies(app, client):
    cast_three(app, client)
    with app.app_context():
        valid, problems = verify(app)
        assert len(valid) == 3 and problems == []


def test_modified_ballot_is_rejected_and_flagged(app, client):
    cast_three(app, client)
    with app.app_context():
        b = db.session.get(CastBallot, 2)
        b.ciphertext = bytes([b.ciphertext[0] ^ 1]) + b.ciphertext[1:]
        db.session.commit()
        result = run_tally()
        assert result["counted"] == 2
        assert result["rejected"][0]["seq"] == 2
        assert IntegrityAlert.query.count() >= 1


def test_deleted_ballot_is_detected(app, client):
    cast_three(app, client)
    with app.app_context():
        db.session.delete(db.session.get(CastBallot, 2))
        db.session.commit()
        _, problems = verify(app)
        assert any("gap" in r for _, r in problems)


def test_deleting_last_ballot_is_detected(app, client):
    cast_three(app, client)
    with app.app_context():
        db.session.delete(db.session.get(CastBallot, 3))
        db.session.commit()
        _, problems = verify(app)
        assert any("chain head" in r for _, r in problems)


def test_forged_ballot_without_integrity_key_is_detected(app, client):
    """Attacker with DB write access inserts a well-formed ballot and even
    computes a correct digest, but can't produce the HMAC without the key."""
    cast_three(app, client)
    with app.app_context():
        keys = app.extensions["keys"]
        bid = str(uuid.uuid4())
        enc = encrypt_ballot({"house": [4, 3, 2, 1]}, keys.ballot_public_key(), bid)
        digest = ballot_digest(bid, "federal-2026", "Melbourne", enc)
        last = db.session.get(CastBallot, 3)
        db.session.add(CastBallot(seq=4, ballot_id=bid, election_id="federal-2026", division="Melbourne",
                                  ciphertext=enc.ciphertext, nonce=enc.nonce, wrapped_key=enc.wrapped_key,
                                  digest=digest, chain_mac=chain_mac(b"guessed-key", last.chain_mac, digest)))
        db.session.commit()
        valid, problems = verify(app)
        assert len(valid) == 3
        assert any(seq == 4 and "chain" in r for seq, r in problems)


def test_swapped_rows_are_detected(app, client):
    cast_three(app, client)
    with app.app_context():
        a, b = db.session.get(CastBallot, 1), db.session.get(CastBallot, 2)
        fields = ("ballot_id", "ciphertext", "nonce", "wrapped_key", "digest", "chain_mac")
        va, vb = [getattr(a, f) for f in fields], [getattr(b, f) for f in fields]
        a.ballot_id, b.ballot_id = "tmp-a", "tmp-b"
        db.session.flush()
        for f, x, y in zip(fields, vb, va):
            setattr(a, f, x); setattr(b, f, y)
        db.session.commit()
        _, problems = verify(app)
        assert problems


def test_tally_counts_first_preferences(app, client):
    cast_three(app, client)
    with app.app_context():
        result = run_tally()
        assert result["counted"] == 3 and result["rejected"] == []
        assert sum(result["first_preferences"]["Melbourne"].values()) == 3
