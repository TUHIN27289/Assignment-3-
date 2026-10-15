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
                                   "ballots_rejected", "exhausted_ballots", "reconciliation_ok", "excluded_candidates",
                                   "divisions"}
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


def _break_reconciliation(app):
    from app.extensions import db
    from app.models import Voter
    with app.app_context():
        Voter.query.filter_by(ballot_issued=True).first().ballot_issued = False
        db.session.commit()


def test_failed_reconciliation_blocks_publication(app, client):
    from app.models import AuditEvent, ResultsPackage
    for e in ("voter1@test.local", "voter2@test.local"):
        vote(app, app.test_client(), e)
    _break_reconciliation(app)
    c = login(client, "tally@test.local", "pw-tally")
    r = client.post("/api/tally/run", headers={"X-CSRF-Token": c}).get_json()
    assert r["reconciliation"]["ok"] is False and r["signed_package"] is None
    assert r["counted"] == 2  # the officer still sees the numbers to investigate
    assert app.test_client().get("/api/results/latest").status_code == 404
    with app.app_context():
        assert ResultsPackage.query.count() == 0
        assert AuditEvent.query.filter_by(event="results_publication_blocked").count() == 1


def test_package_cannot_be_signed_when_reconciliation_fails(app):
    import pytest
    from app.results import ReconciliationFailed, create_package
    with app.app_context(), pytest.raises(ReconciliationFailed):
        create_package({"counted": 0, "rejected": [], "excluded": [], "first_preferences": {},
                        "reconciliation": {"ok": False}})


def test_every_candidate_listed_including_zero_votes(app, client):
    pkg = publish(app, client, voters=("voter1@test.local",))
    melbourne = pkg["package"]["divisions"]["Melbourne"]
    assert set(melbourne) == {"Adams", "Brown", "Chen", "Davis"}
    assert sum(melbourne.values()) == 1 and list(melbourne.values()).count(0) == 3


def test_only_tally_can_create(app, client):
    c = login(client, "voter1@test.local", "pw-voter")
    assert client.post("/api/tally/run", headers={"X-CSRF-Token": c}).status_code == 403
    assert app.test_client().get("/api/results/latest").status_code == 404


def _offline_files(tmp_path, client, pkg):
    pkg_file, keys_file = tmp_path / "package.json", tmp_path / "keys.json"
    pkg_file.write_text(json.dumps(pkg))
    keys_file.write_text(json.dumps(client.get("/api/keys/public").get_json()))
    return str(pkg_file), str(keys_file)


def test_offline_verifier_accepts_genuine_package(app, client, tmp_path):
    import subprocess, sys, pathlib
    pkg = publish(app, client)
    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_results.py"
    out = subprocess.run([sys.executable, str(script), *_offline_files(tmp_path, client, pkg)],
                         capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.startswith("VALID")


def test_offline_verifier_rejects_changed_numbers(app, client, tmp_path):
    import subprocess, sys, pathlib
    pkg = publish(app, client)
    div = next(iter(pkg["package"]["divisions"]))
    cand = next(iter(pkg["package"]["divisions"][div]))
    pkg["package"]["divisions"][div][cand] += 1000
    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_results.py"
    out = subprocess.run([sys.executable, str(script), *_offline_files(tmp_path, client, pkg)],
                         capture_output=True, text=True)
    assert out.returncode == 1 and "does NOT match" in out.stdout


def test_offline_verifier_rejects_untrusted_key(app, client, tmp_path):
    """Someone signs fake results with their own key and claims the AEC's key id."""
    import base64
    import importlib.util
    import pathlib
    from cryptography.hazmat.primitives.asymmetric import ed25519
    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_results.py"
    spec = importlib.util.spec_from_file_location("verify_results", script)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    pkg = publish(app, client)
    forged = dict(pkg, package=dict(pkg["package"], ballots_counted=999))
    forged["signature"] = base64.urlsafe_b64encode(
        ed25519.Ed25519PrivateKey.generate().sign(verifier.canonical(forged["package"]))).decode()
    forged.pop("sha256")
    keys = verifier.load_keys(json.dumps(client.get("/api/keys/public").get_json()))
    valid, message = verifier.verify(forged, keys)
    assert not valid and "does NOT match" in message


def test_verify_refuses_oversized_body(app, client):
    big = {"package": {"padding": "x" * (300 * 1024)}, "kid": "0" * 16, "signature": "x"}
    c = app.test_client()
    r = c.post("/api/results/verify", json=big, headers={"X-CSRF-Token": csrf(c)})
    assert r.status_code == 413


def test_verify_is_rate_limited(app, client):
    c = app.test_client()
    body = {"package": {}, "kid": "0" * 16, "signature": "x"}
    codes = [c.post("/api/results/verify", json=body, headers={"X-CSRF-Token": csrf(c)}).status_code
             for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429


def test_totals_plus_exhausted_add_up_to_ballots_counted(app, client):
    """A voter who only ranked excluded candidates counts as exhausted, not as a vanished ballot."""
    from app.extensions import db
    from app.models import Candidate
    for e in ("voter1@test.local", "voter2@test.local"):
        vote(app, app.test_client(), e)
    with app.app_context():
        for c in Candidate.query.all():  # exclude everyone (as approved court orders would)
            c.excluded, c.exclusion_reason = True, "Court of Disputed Returns order 2026/17"
        db.session.commit()
    c = login(client, "tally@test.local", "pw-tally")
    pkg = client.post("/api/tally/run", headers={"X-CSRF-Token": c}).get_json()["signed_package"]["package"]
    votes = sum(n for counts in pkg["divisions"].values() for n in counts.values())
    assert pkg["exhausted_ballots"] == 2
    assert votes + pkg["exhausted_ballots"] == pkg["ballots_counted"] == 2


def _tally_with(app, client, **settings):
    for e in ("voter1@test.local",):
        vote(app, app.test_client(), e)
    app.config.update(settings)
    c = login(client, "tally@test.local", "pw-tally")
    return client.post("/api/tally/run", headers={"X-CSRF-Token": c})


def _no_decryption(app, monkeypatch):
    def fail():
        raise AssertionError("a ballot was decrypted while voting was open")
    monkeypatch.setattr(app.extensions["keys"], "ballot_private_key", fail)


def test_nothing_counted_while_voting_is_open(app, client, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app.models import AuditEvent
    _no_decryption(app, monkeypatch)
    later = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    r = _tally_with(app, client, ELECTION_CLOSES_AT=later)
    assert r.status_code == 409 and "still open" in r.get_json()["message"]
    assert "first_preferences" not in r.get_json()  # no early numbers, not even for the officer
    assert app.test_client().get("/api/results/latest").status_code == 404
    with app.app_context():
        assert AuditEvent.query.filter_by(event="tally_refused_voting_open").count() == 1


def test_reconciliation_still_available_while_voting_is_open(app, client):
    from datetime import datetime, timedelta, timezone
    later = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    _tally_with(app, client, ELECTION_CLOSES_AT=later)
    t = login(client, "tally@test.local", "pw-tally")
    assert client.post("/api/tally/reconcile", headers={"X-CSRF-Token": t}).get_json()["ok"] is True


def test_counted_and_published_after_close(app, client):
    from datetime import datetime, timedelta, timezone
    earlier = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    r = _tally_with(app, client, ELECTION_CLOSES_AT=earlier).get_json()
    assert r["counted"] == 1 and r["signed_package"] is not None


def test_production_needs_a_close_time(app, client, monkeypatch):
    _no_decryption(app, monkeypatch)
    r = _tally_with(app, client, APP_ENV="production", ELECTION_CLOSES_AT=None)
    assert r.status_code == 409 and "ELECTION_CLOSES_AT" in r.get_json()["message"]


def test_invalid_close_time_refuses_to_count(app, client, monkeypatch):
    _no_decryption(app, monkeypatch)
    r = _tally_with(app, client, ELECTION_CLOSES_AT="next tuesday")
    assert r.status_code == 409 and "not a valid" in r.get_json()["message"]
