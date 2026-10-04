from flask import Blueprint, jsonify, request, current_app
from app.db import get_db_connection
from app.models import Voter

main_bp = Blueprint("main", __name__)

@main_bp.route("/health", methods=["GET"])
def health_check():
    """Minimal health check endpoint to confirm backend availability."""
    return jsonify({
        "status": "healthy",
        "service": "voting-backend"
    }), 200

@main_bp.route("/api/v1/votes/cast", methods=["POST"])
def cast_vote():
    """
    API endpoint for atomic one-vote enforcement (SR-09).
    Delegates atomic eligibility check and state transition to Voter.cast_vote_once.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "status": "INVALID_IDENTIFIER",
            "message": "Request payload must be valid JSON."
        }), 400

    data = request.get_json(silent=True) or {}
    voter_identifier = data.get("voter_identifier")

    if not voter_identifier or not isinstance(voter_identifier, str) or not voter_identifier.strip():
        return jsonify({
            "success": False,
            "status": "INVALID_IDENTIFIER",
            "message": "A voter identifier is required."
        }), 400

    voter_identifier = voter_identifier.strip()
    database_url = current_app.config.get("DATABASE_URL")
    conn = get_db_connection(database_url)

    try:
        result = Voter.cast_vote_once(conn, voter_identifier)
    except Exception:
        return jsonify({
            "success": False,
            "status": "SERVER_ERROR",
            "message": "An internal server error occurred."
        }), 500
    finally:
        conn.close()

    status_code_map = {
        "SUCCESS": 200,
        "ALREADY_VOTED": 409,
        "INELIGIBLE": 403,
        "NOT_FOUND": 404,
        "INVALID_IDENTIFIER": 400
    }

    http_status = status_code_map.get(result.get("status"), 400)

    return jsonify({
        "success": result.get("success", False),
        "status": result.get("status", "FAILED"),
        "message": result.get("message", "Request processing failed.")
    }), http_status
