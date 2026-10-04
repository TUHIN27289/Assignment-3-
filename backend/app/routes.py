from flask import Blueprint, jsonify

main_bp = Blueprint("main", __name__)

@main_bp.route("/health", methods=["GET"])
def health_check():
    """Minimal health check endpoint to confirm backend availability."""
    return jsonify({
        "status": "healthy",
        "service": "voting-backend"
    }), 200
