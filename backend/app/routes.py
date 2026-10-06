from flask import Blueprint, jsonify, request, current_app
from app.db import get_db_connection
from app.models import Voter
from app.receipts import ReceiptService
from app.validators import BallotValidator
from app.ip_validator import DiplomaticIPValidator

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
    API endpoint for atomic one-vote enforcement, ballot validation, receipt generation, and diplomatic IP restriction (SR-09, SR-10, SR-11, SR-12).
    Validates diplomatic mission IP range, ballot structure, and preference ordering before any database state or receipt is persisted.
    """
    # Enforce SR-12 Diplomatic Mission IP Authorization before DB operations or payload processing
    client_ip = DiplomaticIPValidator.extract_client_ip(request)
    allowed_ip_ranges = current_app.config.get("DIPLOMATIC_MISSION_IP_RANGES")

    if not DiplomaticIPValidator.is_ip_allowed(client_ip, allowed_ip_ranges):
        return jsonify({
            "success": False,
            "status": "IP_NOT_ALLOWED",
            "message": "Voting access is restricted to authorized diplomatic mission networks."
        }), 403
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

    # If preferences or ballot details are provided, run server-side ballot validation (SR-11)
    if "preferences" in data or "ballot" in data:
        # Provide fallback election_id if not explicitly provided in ballot payload
        ballot_data = dict(data)
        if "election_id" not in ballot_data or not ballot_data["election_id"]:
            ballot_data["election_id"] = "DEFAULT-ELECTION"

        val_result = BallotValidator.validate_ballot_structure(ballot_data)
        if not val_result["is_valid"]:
            return jsonify({
                "success": False,
                "status": "INVALID_BALLOT",
                "message": "Ballot validation failed.",
                "errors": val_result["errors"]
            }), 400

    database_url = current_app.config.get("DATABASE_URL")
    secret_key = current_app.config.get("RECEIPT_SECRET_KEY") or current_app.config.get("SECRET_KEY")
    conn = get_db_connection(database_url)

    try:
        # 1. Perform atomic voter update without committing immediately (SR-09)
        cast_result = Voter.cast_vote_once(conn, voter_identifier, auto_commit=False)

        if not cast_result.get("success"):
            try:
                conn.rollback()
            except Exception:
                pass
            status_code_map = {
                "ALREADY_VOTED": 409,
                "INELIGIBLE": 403,
                "NOT_FOUND": 404,
                "INVALID_IDENTIFIER": 400
            }
            http_status = status_code_map.get(cast_result.get("status"), 400)
            return jsonify({
                "success": False,
                "status": cast_result.get("status", "FAILED"),
                "message": cast_result.get("message", "Request processing failed.")
            }), http_status

        # 2. Extract authoritative voted_at from the successful atomic UPDATE
        voted_at = cast_result["voter"]["voted_at"]

        # 3. Create signed receipt within the same transaction (SR-10)
        receipt = ReceiptService.create_receipt(
            conn,
            voter_identifier=voter_identifier,
            voted_at=voted_at,
            secret_key=secret_key,
            auto_commit=False
        )

        # 4. Commit BOTH voter update and receipt creation in one logical transaction
        conn.commit()

        return jsonify({
            "success": True,
            "status": "SUCCESS",
            "message": "Vote recorded successfully.",
            "receipt": {
                "tracking_code": receipt["tracking_code"],
                "voter_identifier": receipt["voter_identifier"],
                "voted_at": receipt["voted_at"],
                "signature": receipt["signature"]
            }
        }), 200

    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return jsonify({
            "success": False,
            "status": "SERVER_ERROR",
            "message": "An internal server error occurred."
        }), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass
