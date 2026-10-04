import pytest
from app.db import get_db_connection
from app.models import Voter

def test_cast_vote_valid_eligible_voter(client, app):
    """Test 1: POST /api/v1/votes/cast with a valid eligible voter returns HTTP 200 and SUCCESS status."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-100", is_eligible=True, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-100"})
    assert response.status_code == 200

    data = response.get_json()
    assert data["success"] is True
    assert data["status"] == "SUCCESS"
    assert data["message"] == "Vote recorded successfully."

    # Verify database state updated
    conn = get_db_connection(app.config["DATABASE_URL"])
    voter = Voter.get_by_identifier(conn, "VOTER-API-100")
    conn.close()
    assert voter["has_voted"] is True
    assert voter["voted_at"] is not None

def test_cast_vote_already_voted(client, app):
    """Test 2: POST /api/v1/votes/cast for an already voted voter returns HTTP 409 ALREADY_VOTED."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-101", is_eligible=True, has_voted=True, voted_at="2026-10-04 10:00:00")
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-101"})
    assert response.status_code == 409

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "ALREADY_VOTED"

def test_cast_vote_ineligible_voter(client, app):
    """Test 3: POST /api/v1/votes/cast for an ineligible voter returns HTTP 403 INELIGIBLE."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-API-102", is_eligible=False, has_voted=False)
    conn.close()

    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "VOTER-API-102"})
    assert response.status_code == 403

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "INELIGIBLE"

def test_cast_vote_non_existent_voter(client, app):
    """Test 4: POST /api/v1/votes/cast for a non-existent voter returns HTTP 404 NOT_FOUND."""
    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "NON-EXISTENT-VOTER"})
    assert response.status_code == 404

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "NOT_FOUND"

def test_cast_vote_missing_voter_identifier(client):
    """Test 5: POST /api/v1/votes/cast without voter_identifier returns HTTP 400 INVALID_IDENTIFIER."""
    response = client.post("/api/v1/votes/cast", json={})
    assert response.status_code == 400

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "INVALID_IDENTIFIER"

def test_cast_vote_empty_voter_identifier(client):
    """Test 6: POST /api/v1/votes/cast with empty/whitespace voter_identifier returns HTTP 400 INVALID_IDENTIFIER."""
    response = client.post("/api/v1/votes/cast", json={"voter_identifier": "   "})
    assert response.status_code == 400

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "INVALID_IDENTIFIER"

def test_cast_vote_non_json_request(client):
    """Test 7: POST /api/v1/votes/cast with non-JSON payload returns HTTP 400 INVALID_IDENTIFIER."""
    response = client.post("/api/v1/votes/cast", data="plain-text-payload", content_type="text/plain")
    assert response.status_code == 400

    data = response.get_json()
    assert data["success"] is False
    assert data["status"] == "INVALID_IDENTIFIER"

def test_cast_vote_security_boundary_strips_extra_fields(client, app):
    """Test 8: Security boundary test ensuring client cannot manipulate has_voted or is_eligible flags."""
    conn = get_db_connection(app.config["DATABASE_URL"])
    Voter.create(conn, "VOTER-SECURITY-10", is_eligible=False, has_voted=False)
    conn.close()

    # Attempt to pass is_eligible=True and has_voted=True in JSON body
    response = client.post("/api/v1/votes/cast", json={
        "voter_identifier": "VOTER-SECURITY-10",
        "is_eligible": True,
        "has_voted": True
    })

    # Should still be rejected because database authority determines eligibility
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "INELIGIBLE"
