"""SR-01: TOTP multi-factor authentication for every staff account.

After a correct password, staff get a short "MFA pending" session that has
no permissions. They must then either set up an authenticator app (first
login) or enter a current 6-digit code.

- The TOTP secret is encrypted with AES-GCM under the MFA key before it's
  stored, with the user id bound in so a secret can't be copied to another row.
- A code is accepted for the current 30 s step or one step either side
  (clock drift), and each step can only be used once (no replay).
- Wrong codes count towards the same lockout as wrong passwords (SR-03).
- The pending state expires after 5 minutes.
"""
import hmac
import os
import time

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import abort, current_app, jsonify, request, session

from .. import audit
from ..extensions import db, limiter
from ..models import User
from ..security.http import get_csrf_token
from ..security.rbac import public
from . import _now, bp, register_failed_attempt, start_session

PENDING_TTL = 300
ISSUER = "AEC Voting Platform"


def _aesgcm():
    return AESGCM(current_app.extensions["keys"].mfa_key())


def encrypt_secret(user_id, secret):
    nonce = os.urandom(12)
    return nonce + _aesgcm().encrypt(nonce, secret.encode(), str(user_id).encode())


def decrypt_secret(user_id, blob):
    return _aesgcm().decrypt(blob[:12], blob[12:], str(user_id).encode()).decode()


def check_code(user, code, now=None):
    """True if code is valid for a step not used before. Records the step."""
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(decrypt_secret(user.id, user.mfa_secret_enc))
    current = int((now or time.time()) // 30)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            if user.mfa_last_step is not None and step <= user.mfa_last_step:
                return False  # already used
            user.mfa_last_step = step
            return True
    return False


def _pending_user():
    uid, started = session.get("mfa_uid"), session.get("mfa_started", 0)
    if uid is None or time.time() - started > PENDING_TTL:
        session.clear()
        abort(401)
    user = db.session.get(User, uid)
    if user is None or (user.locked_until and user.locked_until > _now()):
        session.clear()
        abort(401)
    return user


@bp.post("/mfa/setup")
@public
@limiter.limit("5 per minute")
def mfa_setup():
    user = _pending_user()
    if user.mfa_enabled:
        abort(409, description="MFA already set up")
    secret = pyotp.random_base32()
    user.mfa_secret_enc = encrypt_secret(user.id, secret)
    user.mfa_last_step = None
    db.session.commit()
    audit.record("mfa_setup_started", user.id)
    return jsonify(
        secret=secret,
        otpauth_uri=pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=ISSUER),
    )


@bp.post("/mfa/verify")
@public
@limiter.limit("5 per minute")
def mfa_verify():
    user = _pending_user()
    if user.mfa_secret_enc is None:
        abort(400, description="MFA not set up")
    code = (request.get_json(silent=True) or {}).get("code")
    if not check_code(user, code):
        register_failed_attempt(user, "wrong MFA code")
        abort(401)

    first_time = not user.mfa_enabled
    user.mfa_enabled = True
    user.failed_logins = 0
    db.session.commit()
    start_session(user)
    if first_time:
        audit.record("mfa_enabled", user.id)
    audit.record("login_ok", user.id, mfa=True)
    return jsonify(role=user.role, csrf_token=get_csrf_token())
