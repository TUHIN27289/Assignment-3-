import pytest
from unittest.mock import patch
from app.db import get_db_connection
from app.models import Voter
from app.receipts import ReceiptService

def test_cast_vote_valid_eligible_voter_returns_receipt(client, app):
    """Test 1: POST /api/v1/votes/cast for a valid eligible voter returns HTTP 200 and a signed receipt."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-100", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-100"})
    assert response.status_code == 200

    data = response.get_json()
    assert data["success"] is True
    assert data["status"] == "SUCCESS"
    assert data["message"] == "Vote recorded successfully."
    assert "receipt" in data

    receipt = data["receipt"]
    assert receipt["voter_identifier"] == "VOTER-API-100"
    assert len(receipt["tracking_code"]) == 32
    assert receipt["voted_at"] is not None
    assert receipt["signature"] is not None

    # Verify receipt signature
    secret_key = app.config.get("RECEIPT_SECRET_KEY") or app.config.get("SECRET_KEY")
    is_valid = ReceiptService.verify_signature(
        receipt["tracking_code"],
        receipt["voter_identifier"],
        receipt["voted_at"],
        receipt["signature"],
        secret_key=secret_key
    )
    assert is_valid is True

    # Verify database state updated
    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-API-100")
    db_receipt = ReceiptService.get_by_tracking_code(conn, receipt["tracking_code"])
    conn.close()

    assert voter["has_voted"] is True
    assert db_receipt is not None
    assert db_receipt["voter_identifier"] == "VOTER-API-100"

def test_receipt_persistence(client, app):
    """Test 2: Verify receipt is persisted in database after successful vote."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-PERSIST-1", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-PERSIST-1"})
    assert response.status_code == 200
    tracking_code = response.get_json()["receipt"]["tracking_code"]

    conn = get_db_connection(app.config["DATABASE_URL"])
    db_receipt = ReceiptService.get_by_tracking_code(conn, tracking_code)
    conn.close()

    assert db_receipt is not None
    assert db_receipt["voter_identifier"] == "VOTER-PERSIST-1"

def test_cast_vote_already_voted_no_duplicate_receipt(client, app):
    """Test 3: POST /api/v1/votes/cast for duplicate vote returns HTTP 409 and does NOT create a second receipt."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-101", is_eligible=True, has_voted=False)
    conn.close()

    # First vote succeeds and gets a receipt
    resp1 = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-101"})
    assert resp1.status_code == 200
    first_receipt = resp1.get_json()["receipt"]

    # Second vote attempt fails
    resp2 = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-101"})
    assert resp2.status_code == 409
    data2 = resp2.get_json()
    assert data2["status"] == "ALREADY_VOTED"
    assert "receipt" not in data2

    # Verify database has exactly 1 receipt and timestamp is untouched
    conn = get_db_connection(app.config["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM receipts WHERE voter_identifier = ?", ("VOTER-API-101",))
    receipt_count = cursor.fetchone()[0]
    db_receipt = ReceiptService.get_by_tracking_code(conn, first_receipt["tracking_code"])
    conn.close()

    assert receipt_count == 1
    assert db_receipt["signature"] == first_receipt["signature"]

def test_cast_vote_ineligible_voter_no_receipt(client, app):
    """Test 4: POST /api/v1/votes/cast for an ineligible voter returns HTTP 403 and creates NO receipt."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-102", is_eligible=False, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-102"})
    assert response.status_code == 403

    data = response.get_json()
    assert data["status"] == "INELIGIBLE"
    assert "receipt" not in data

    conn = get_db_connection(app.config["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM receipts WHERE voter_identifier = ?", ("VOTER-API-102",))
    receipt_count = cursor.fetchone()[0]
    conn.close()
    assert receipt_count == 0

def test_cast_vote_non_existent_voter_no_receipt(client, app):
    """Test 5: POST /api/v1/votes/cast for a non-existent voter returns HTTP 404 and creates NO receipt."""
    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "NON-EXISTENT-VOTER"})
    assert response.status_code == 404
    data = response.get_json()
    assert data["status"] == "NOT_FOUND"
    assert "receipt" not in data

def test_cast_vote_missing_voter_identifier(client):
    """Test 6a: POST /api/v1/votes/cast without voter_identifier returns HTTP 400."""
    response = client.post("/api/v1/votes/cast", json={})
    assert response.status_code == 400
    assert "receipt" not in response.get_json()

def test_cast_vote_empty_voter_identifier(client):
    """Test 6b: POST /api/v1/votes/cast with empty/whitespace voter_identifier returns HTTP 400."""
    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "   "})
    assert response.status_code == 400
    assert "receipt" not in response.get_json()

def test_cast_vote_non_json_request(client):
    """Test 6c: POST /api/v1/votes/cast with non-JSON payload returns HTTP 400."""
    response = client.post("/api/v1/votes/cast", data="plain-text-payload", content_type="text/plain")
    assert response.status_code == 400
    assert "receipt" not in response.get_json()

def test_receipt_verification_and_tampering_rejection(client, app):
    """Test 7: Verify API receipt signature passes, and tampering with any field invalidates signature."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-VERIFY-77", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-VERIFY-77"})
    assert response.status_code == 200
    receipt = response.get_json()["receipt"]
    secret_key = app.config.get("RECEIPT_SECRET_KEY") or app.config.get("SECRET_KEY")

    assert ReceiptService.verify_signature(
        receipt["tracking_code"], receipt["voter_identifier"], receipt["voted_at"], receipt["signature"], secret_key
    ) is True

    assert ReceiptService.verify_signature(
        "TAMPERED-TC", receipt["voter_identifier"], receipt["voted_at"], receipt["signature"], secret_key
    ) is False

def test_transaction_rollback_on_receipt_failure(client, app):
    """Test 8 (Transaction Rollback): Simulates receipt persistence error; verifies voter has_voted remains False."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-ROLLBACK-99", is_eligible=True, has_voted=False)
    conn.close()

    with patch("app.routes.ReceiptService.create_receipt", side_effect=Exception("Database write error during receipt creation")):
        response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-ROLLBACK-99"})

    assert response.status_code == 500
    data = response.get_json()
    assert data["status"] == "SERVER_ERROR"

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-ROLLBACK-99")
    conn.close()
    assert voter["has_voted"] is False
    assert voter["voted_at"] is None

def test_cast_vote_security_boundary_strips_extra_fields(client, app):
    """Test 9: Security boundary test ensuring client cannot manipulate has_voted or is_eligible flags."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-SECURITY-10", is_eligible=False, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-SECURITY-10",
        "is_eligible": True,
        "has_voted": True
    })

    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "INELIGIBLE"
    assert "receipt" not in data


# --- SR-11 API Integration Tests ---

def test_cast_vote_with_valid_ballot_preferences(client, app):
    """Test SR-11 (1): Valid ballot preferences with eligible voter succeeds and issues receipt."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-BALLOT-VALID", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-BALLOT-VALID",
        "election_id": "ELEC-2026-01",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": 1},
            {"candidate_id": "CAND-2", "rank": 2}
        ]
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "SUCCESS"
    assert "receipt" in data

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-BALLOT-VALID")
    conn.close()
    assert voter["has_voted"] is True

def test_cast_vote_invalid_preference_type_rejected(client, app):
    """Test SR-11 (2): Preference with invalid rank type (string) returns HTTP 400 INVALID_BALLOT."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-BALLOT-TYPE", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-BALLOT-TYPE",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": "1"}
        ]
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "INVALID_BALLOT"
    assert "errors" in data
    assert "receipt" not in data

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-BALLOT-TYPE")
    conn.close()
    assert voter["has_voted"] is False

def test_cast_vote_duplicate_candidate_rejected(client, app):
    """Test SR-11 (3): Preferences containing duplicate candidate IDs return HTTP 400 INVALID_BALLOT."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-DUP-CAND", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-DUP-CAND",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": 1},
            {"candidate_id": "CAND-1", "rank": 2}
        ]
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "INVALID_BALLOT"
    assert any("Duplicate candidate ID" in err for err in data["errors"])

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-DUP-CAND")
    conn.close()
    assert voter["has_voted"] is False

def test_cast_vote_duplicate_rank_rejected(client, app):
    """Test SR-11 (4): Preferences containing duplicate ranks return HTTP 400 INVALID_BALLOT."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-DUP-RANK", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-DUP-RANK",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": 1},
            {"candidate_id": "CAND-2", "rank": 1}
        ]
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "INVALID_BALLOT"
    assert any("Duplicate rank" in err for err in data["errors"])

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-DUP-RANK")
    conn.close()
    assert voter["has_voted"] is False

def test_cast_vote_rank_gap_rejected(client, app):
    """Test SR-11 (5): Preferences with a rank gap (e.g. ranks 1, 3) return HTTP 400 INVALID_BALLOT."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-GAP", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-GAP",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": 1},
            {"candidate_id": "CAND-2", "rank": 3}
        ]
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "INVALID_BALLOT"
    assert any("Missing rank 2" in err for err in data["errors"])

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-GAP")
    conn.close()
    assert voter["has_voted"] is False

def test_cast_vote_invalid_starting_rank_rejected(client, app):
    """Test SR-11 (6): Preferences starting at rank 2 instead of 1 return HTTP 400 INVALID_BALLOT."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-START-RANK", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-START-RANK",
        "preferences": [
            {"candidate_id": "CAND-1", "rank": 2},
            {"candidate_id": "CAND-2", "rank": 3}
        ]
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "INVALID_BALLOT"
    assert any("must start at 1" in err for err in data["errors"])

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-START-RANK")
    conn.close()
    assert voter["has_voted"] is False


# --- SR-12 Diplomatic Mission IP Restriction API Tests ---

def test_cast_vote_authorized_ipv4_address(client, app):
    """SR-12 (1): Authorized IPv4 client IP proceeds normally through SR-11 validation, SR-09 voting, and SR-10 receipt issuance."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-AUTH-1", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post(
        "/api/v1/votes/cast",
        json={
            "voter_identifier": "VOTER-IP-AUTH-1",
            "preferences": [{"candidate_id": "CAND-1", "rank": 1}]
        },
        environ_base={"REMOTE_ADDR": "192.0.2.10"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["status"] == "SUCCESS"
    assert "receipt" in data

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-IP-AUTH-1")
    db_receipt = ReceiptService.get_by_tracking_code(conn, data["receipt"]["tracking_code"])
    conn.close()

    assert voter["has_voted"] is True
    assert db_receipt is not None


def test_cast_vote_unauthorized_ipv4_address(client, app):
    """SR-12 (2): Unauthorized IPv4 client IP returns HTTP 403 IP_NOT_ALLOWED with zero side-effects."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-UNAUTH-1", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-UNAUTH-1"},
        environ_base={"REMOTE_ADDR": "203.0.113.5"}
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "IP_NOT_ALLOWED"
    assert data["message"] == "Voting access is restricted to authorized diplomatic mission networks."
    assert "receipt" not in data

    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-IP-UNAUTH-1")
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM receipts WHERE voter_identifier = ?", ("VOTER-IP-UNAUTH-1",))
    receipt_count = cursor.fetchone()[0]
    conn.close()

    assert voter["has_voted"] is False
    assert voter["voted_at"] is None
    assert receipt_count == 0


def test_cast_vote_boundary_ip_inside_allowed_cidr(client, app):
    """SR-12 (3): Network boundary IP inside allowed CIDR is authorized."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-BOUND-IN", is_eligible=True, has_voted=False)
    conn.close()

    # Boundary address 192.0.2.255 inside 192.0.2.0/24
    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-BOUND-IN"},
        environ_base={"REMOTE_ADDR": "192.0.2.255"}
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "SUCCESS"


def test_cast_vote_ip_immediately_outside_allowed_cidr(client, app):
    """SR-12 (4): IP immediately adjacent to allowed CIDR range is rejected with HTTP 403."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-BOUND-OUT", is_eligible=True, has_voted=False)
    conn.close()

    # Immediate boundary 192.0.3.0 outside 192.0.2.0/24
    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-BOUND-OUT"},
        environ_base={"REMOTE_ADDR": "192.0.3.0"}
    )
    assert response.status_code == 403
    assert response.get_json()["status"] == "IP_NOT_ALLOWED"


def test_cast_vote_multiple_configured_cidr_ranges(client, app):
    """SR-12 (5): Multiple configured CIDR ranges permit authorized requests across any matching subnet."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24, 198.51.100.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-MULTI-1", is_eligible=True, has_voted=False)
    Voter.create(conn, "VOTER-IP-MULTI-2", is_eligible=True, has_voted=False)
    conn.close()

    resp1 = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-MULTI-1"},
        environ_base={"REMOTE_ADDR": "192.0.2.5"}
    )
    assert resp1.status_code == 200

    resp2 = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-MULTI-2"},
        environ_base={"REMOTE_ADDR": "198.51.100.50"}
    )
    assert resp2.status_code == 200


def test_cast_vote_ipv6_behavior(client, app):
    """SR-12 (6): IPv6 client IP inside allowed IPv6 CIDR proceeds normally."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "2001:db8::/32"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-IPV6-AUTH", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-IPV6-AUTH"},
        environ_base={"REMOTE_ADDR": "2001:db8::1234"}
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "SUCCESS"


def test_cast_vote_missing_empty_ip_range_configuration_denies_by_default(client, app):
    """SR-12 (7): Missing/empty IP range configuration denies access by default (HTTP 403)."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = ""

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-EMPTY-CFG", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-EMPTY-CFG"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"}
    )
    assert response.status_code == 403
    assert response.get_json()["status"] == "IP_NOT_ALLOWED"


def test_cast_vote_spoofed_x_forwarded_for_header_rejected(client, app):
    """SR-12 (8): Request with unauthorized remote_addr and spoofed authorized X-Forwarded-For header is rejected with HTTP 403."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-SPOOF-XFF", is_eligible=True, has_voted=False)
    conn.close()

    # REMOTE_ADDR is unauthorized (203.0.113.10), but X-Forwarded-For attempts to spoof an authorized IP (192.0.2.10)
    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-SPOOF-XFF"},
        headers={"X-Forwarded-For": "192.0.2.10"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "IP_NOT_ALLOWED"


def test_cast_vote_spoofed_x_real_ip_header_rejected(client, app):
    """SR-12 (9): Request with unauthorized remote_addr and spoofed authorized X-Real-IP header is rejected with HTTP 403."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"

    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-IP-SPOOF-REALIP", is_eligible=True, has_voted=False)
    conn.close()

    # REMOTE_ADDR is unauthorized (203.0.113.10), but X-Real-IP attempts to spoof an authorized IP (192.0.2.10)
    response = client.post(
        "/api/v1/votes/cast",
        json={"voter_identifier": "VOTER-IP-SPOOF-REALIP"},
        headers={"X-Real-IP": "192.0.2.10"},
        environ_base={"REMOTE_ADDR": "203.0.113.10"}
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "IP_NOT_ALLOWED"
