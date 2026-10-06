"""SR-16: HTTP hardening for the API.

- Security headers (HSTS, CSP, no framing, no referrer) via Flask-Talisman
- CORS locked to the React frontend's origin only, with credentials
- CSRF protection for a single-page app: synchroniser token kept in the
  server-side session, handed to the frontend by GET /api/auth/csrf and
  sent back in the X-CSRF-Token header on every state-changing request
- Session cookie flags are set in config.py (HttpOnly, Secure, SameSite=Strict)
"""
import hmac
import secrets

from flask import abort, jsonify, request, session
from flask_cors import CORS
from flask_talisman import Talisman

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-CSRF-Token"


def get_csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _check_csrf():
    if request.method in SAFE_METHODS:
        return
    expected = session.get("csrf")
    sent = request.headers.get(CSRF_HEADER, "")
    if not expected or not hmac.compare_digest(expected, sent):
        abort(403, description="CSRF token missing or invalid")


def _no_store(response):
    # API responses can carry ballot tokens and personal data, never cache them
    response.headers["Cache-Control"] = "no-store"
    return response


def init_http_security(app):
    Talisman(
        app,
        force_https=app.config["FORCE_HTTPS"],
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        # The API only ever returns JSON, so the tightest possible policy works
        content_security_policy={"default-src": "'none'", "frame-ancestors": "'none'"},
        frame_options="DENY",
        referrer_policy="no-referrer",
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=True,
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    CORS(
        app,
        resources={r"/api/*": {"origins": [app.config["FRONTEND_ORIGIN"]]}},
        supports_credentials=True,
        allow_headers=["Content-Type", CSRF_HEADER],
        methods=["GET", "POST", "PUT", "DELETE"],
    )
    app.before_request(_check_csrf)
    app.after_request(_no_store)

    @app.get("/api/auth/csrf")
    def csrf_token():
        return jsonify(csrf_token=get_csrf_token())
