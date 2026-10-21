"""SR-10: Signed voter receipt with tracking code.

Verifies that casting a ballot returns a tracking code and HMAC digital receipt signature.
The receipt proves that the vote was recorded without revealing candidate choices.
"""
import pytest
from app.ballot.crypto import sign_receipt, verify_receipt
from .conftest import csrf, login, vote, candidate_ids


def test_cast_ballot_returns_signed_receipt(app, client):
    """Casting a ballot returns tracking_code and receipt signature."""
    res = vote(app, client, "voter1@test.local")
    assert res.status_code == 200
    data = res.get_json()

    assert "tracking_code" in data
    assert "receipt" in data
    assert len(data["tracking_code"]) == 64  # SHA-256 digest hex
    assert len(data["receipt"]) == 64        # HMAC-SHA256 hex

    # Verify cryptographic signature using server receipt key
    keys = app.extensions["keys"]
    assert verify_receipt(keys.receipt_key(), data["tracking_code"], data["receipt"]) is True


def test_receipt_reveals_no_voting_choices(app, client):
    """Receipt contains only tracking code and signature; no candidate or choice data."""
    res = vote(app, client, "voter1@test.local", prefs=[4, 3, 2, 1])
    assert res.status_code == 200
    data = res.get_json()

    # Must contain only cryptographic receipt fields
    assert set(data.keys()) == {"tracking_code", "receipt"}
    # Verify no candidate IDs or ranking information leaked in the payload
    for k, v in data.items():
        assert "house" not in str(v).lower()
        assert "senate" not in str(v).lower()


def test_receipt_verification_endpoint_success(app, client):
    """POST /api/ballot/receipt/verify returns valid=True for authentic receipt."""
    res = vote(app, client, "voter1@test.local")
    data = res.get_json()

    anon = app.test_client()
    verify_res = anon.post("/api/ballot/receipt/verify", json={
        "tracking_code": data["tracking_code"],
        "receipt": data["receipt"]
    }, headers={"X-CSRF-Token": csrf(anon)})

    assert verify_res.status_code == 200
    assert verify_res.get_json() == {
        "valid": True,
        "tracking_code": data["tracking_code"]
    }


def test_receipt_verification_rejects_tampered_tracking_code(app, client):
    """Tampering with the tracking code causes verification to fail."""
    res = vote(app, client, "voter1@test.local")
    data = res.get_json()

    tampered_code = data["tracking_code"][:-1] + ("0" if data["tracking_code"][-1] != "0" else "1")

    anon = app.test_client()
    verify_res = anon.post("/api/ballot/receipt/verify", json={
        "tracking_code": tampered_code,
        "receipt": data["receipt"]
    }, headers={"X-CSRF-Token": csrf(anon)})

    assert verify_res.status_code == 200
    assert verify_res.get_json()["valid"] is False


def test_receipt_verification_rejects_forged_signature(app, client):
    """Forged receipt signatures fail cryptographic verification."""
    res = vote(app, client, "voter1@test.local")
    data = res.get_json()

    forged_signature = "a" * 64

    anon = app.test_client()
    verify_res = anon.post("/api/ballot/receipt/verify", json={
        "tracking_code": data["tracking_code"],
        "receipt": forged_signature
    }, headers={"X-CSRF-Token": csrf(anon)})

    assert verify_res.status_code == 200
    assert verify_res.get_json()["valid"] is False


def test_receipt_verification_missing_fields(app, client):
    """Missing tracking code or signature returns 400 Bad Request."""
    anon = app.test_client()
    res = anon.post("/api/ballot/receipt/verify", json={}, headers={"X-CSRF-Token": csrf(anon)})
    assert res.status_code == 400


@pytest.mark.parametrize("bad_payload", [
    {"tracking_code": 12345, "receipt": "a" * 64},
    {"tracking_code": "a" * 64, "receipt": 12345},
    {"tracking_code": None, "receipt": "a" * 64},
    {"tracking_code": "a" * 64, "receipt": None},
    {"tracking_code": ["list"], "receipt": "a" * 64},
    {"tracking_code": "a" * 64, "receipt": {"dict": True}},
    {"tracking_code": True, "receipt": False},
    {"tracking_code": "", "receipt": "a" * 64},
    {"tracking_code": "a" * 64, "receipt": "   "},
])
def test_receipt_verification_non_string_types_rejected(app, client, bad_payload):
    """Non-string or empty inputs to /receipt/verify return HTTP 400 instead of 500 error."""
    anon = app.test_client()
    res = anon.post("/api/ballot/receipt/verify", json=bad_payload, headers={"X-CSRF-Token": csrf(anon)})
    assert res.status_code == 400
    assert "missing or invalid" in res.get_json().get("message", "").lower()


def test_sign_and_verify_crypto_unit():
    """Unit test for sign_receipt and verify_receipt helpers."""
    key = b"super-secret-key-for-test-32bytes"
    code = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    sig = sign_receipt(key, code)
    assert isinstance(sig, str) and len(sig) == 64
    assert verify_receipt(key, code, sig) is True

    # Wrong key
    assert verify_receipt(b"wrong-key", code, sig) is False
    # Wrong code
    assert verify_receipt(key, code + "1", sig) is False
    # Non-string parameters return False safely
    assert verify_receipt(key, 12345, sig) is False
    assert verify_receipt(key, code, 12345) is False
    assert verify_receipt(key, None, sig) is False

    # sign_receipt with non-string raises TypeError
    with pytest.raises(TypeError):
        sign_receipt(key, 12345)
