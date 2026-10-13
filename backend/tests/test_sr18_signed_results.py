"""SR-18: signed, aggregate-only results package."""
import base64
import json

from cryptography.hazmat.primitives import serialization

from .conftest import csrf, login, vote


def publish(app, client, voters=("voter1@test.local", "voter2@test.local")):
    for e in voters:
        vote(app, app.test_client(), e)
    c = login(client, "tally@test.local", "pw-tally")
    r = client.post("/api/tally/run", headers={"X-CSRF-Token": c})
    assert r.status_code == 200
    return r.get_json()["signed_package"]


def verify(client, pkg):
    return client.post("/api/results/verify", json={k: pkg[k] for k in ("package", "kid", "signature")},
                       headers={"X-CSRF-Token": csrf(client)}).get_json()["valid"]


def test_signature_verifies_with_published_key(app, client):
    pkg = publish(app, client)
    pem = client.get("/api/keys/public").get_json()["results_signing_keys"][pkg["kid"]]
    body = json.dumps(pkg["package"], sort_keys=True, separators=(",", ":")).encode()
    serialization.load_pem_public_key(pem.encode()).verify(base64.urlsafe_b64decode(pkg["signature"]), body)
    assert verify(app.test_client(), pkg)


def test_changed_numbers_fail_verification(app, client):
    pkg = publish(app, client)
    div = next(iter(pkg["package"]["divisions"]))
    cand = next(iter(pkg["package"]["divisions"][div]))
    pkg["package"]["divisions"][div][cand] += 1000
    assert verify(app.test_client(), pkg) is False


def test_package_holds_aggregates_only(app, client):
    pkg = publish(app, client)
    text = json.dumps(pkg)
    assert set(pkg["package"]) == {"v", "election_id", "sequence", "generated_at", "method", "ballots_counted",
                                   "ballots_rejected", "reconciliation_ok", "excluded_candidates", "divisions"}
    for word in ("ballot_id", "digest", "ciphertext", "tracking", "voter", "token", "seq\""):
        assert word not in text
    for counts in pkg["package"]["divisions"].values():
        assert all(isinstance(v, int) for v in counts.values())


def test_public_can_fetch_latest(app, client):
    pkg = publish(app, client)
    latest = app.test_client().get("/api/results/latest").get_json()
    assert latest["sha256"] == pkg["sha256"] and latest["signature"] == pkg["signature"]


def test_sequence_and_timestamp_are_signed(app, client):
    first = publish(app, client)
    c = login(client, "tally@test.local", "pw-tally")
    second = client.post("/api/tally/run", headers={"X-CSRF-Token": c}).get_json()["signed_package"]
    assert second["package"]["sequence"] == first["package"]["sequence"] + 1
    replayed = dict(first, package=dict(first["package"], sequence=second["package"]["sequence"]))
    assert verify(app.test_client(), replayed) is False


def test_old_package_still_verifies_after_key_rotation(app, client):
    pkg = publish(app, client)
    app.extensions["keys"].rotate("results")
    assert verify(app.test_client(), pkg) is True
    c = login(client, "tally@test.local", "pw-tally")
    newer = client.post("/api/tally/run", headers={"X-CSRF-Token": c}).get_json()["signed_package"]
    assert newer["kid"] != pkg["kid"] and verify(app.test_client(), newer)


def test_unknown_kid_fails(app, client):
    pkg = publish(app, client)
    assert verify(app.test_client(), dict(pkg, kid="0" * 16)) is False


def test_failed_reconciliation_is_signed_in(app, client):
    from app.extensions import db
    from app.models import Voter
    for e in ("voter1@test.local", "voter2@test.local"):
        vote(app, app.test_client(), e)
    with app.app_context():
        Voter.query.filter_by(ballot_issued=True).first().ballot_issued = False
        db.session.commit()
    c = login(client, "tally@test.local", "pw-tally")
    pkg = client.post("/api/tally/run", headers={"X-CSRF-Token": c}).get_json()["signed_package"]
    assert pkg["package"]["reconciliation_ok"] is False


def test_only_tally_can_create(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.post("/api/tally/run", headers={"X-CSRF-Token": c}).status_code == 403
    assert app.test_client().get("/api/results/latest").status_code == 404
