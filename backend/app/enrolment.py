"""Enrolment: the part of the platform that holds voter personal data.

Voters:  GET  /api/enrolment/me          own enrolment status and details
         POST /api/enrolment/me/enrol    enrol themselves if not enrolled yet
         PUT  /api/enrolment/me/address  update their address
Officers: GET  /api/enrolment/voters     list electors (every read is audited)
          POST /api/enrolment/voters     register a citizen

Personal data is encrypted at rest (SR-05, see security/pii.py). The audit
log records who read or changed which record and which fields, but never
the personal values themselves, because the audit log is not encrypted.
"""
import re
import secrets
from datetime import date

from flask import Blueprint, abort, g, jsonify, request

from . import audit
from .auth import hash_password, role_required
from .auth.sessions import recent_auth_required
from .extensions import db
from .models import User, Voter

bp = Blueprint("enrolment", __name__, url_prefix="/api/enrolment")

EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,}$", re.I)
DIVISION = re.compile(r"^[A-Za-z][A-Za-z '\-]{1,63}$")
VOTING_AGE = 18


def _text(data, key, lo, hi):
    v = data.get(key)
    if not isinstance(v, str) or not lo <= len(v.strip()) <= hi:
        abort(400, description=f"{key} must be {lo} to {hi} characters")
    return v.strip()


def _dob(data):
    try:
        d = date.fromisoformat(str(data.get("date_of_birth")))
    except ValueError:
        abort(400, description="date_of_birth must be YYYY-MM-DD")
    today = date.today()
    age = today.year - d.year - ((today.month, today.day) < (d.month, d.day))
    if not 0 <= age <= 130:
        abort(400, description="date_of_birth is not plausible")
    return d, age


def _view(v, email=None):
    out = {"id": v.id, "full_name": v.full_name, "date_of_birth": v.date_of_birth, "address": v.address,
           "division": v.division, "enrolled": v.enrolled}
    if email:
        out["email"] = email
    return out


def _my_voter():
    v = Voter.query.filter_by(user_id=g.user.id).first()
    if v is None:
        abort(404, description="no enrolment record")
    return v


@bp.get("/me")
@role_required("voter")
def me():
    return jsonify(_view(_my_voter()))


@bp.post("/me/enrol")
@role_required("voter")
@recent_auth_required
def self_enrol():
    v = _my_voter()
    if v.enrolled:
        abort(409, description="already enrolled")
    data = request.get_json(silent=True) or {}
    d, age = _dob(data)
    if age < VOTING_AGE:
        abort(403, description="must be 18 or older to enrol to vote")
    v.date_of_birth, v.address = d.isoformat(), _text(data, "address", 5, 200)
    v.enrolled = True
    db.session.commit()
    audit.record("voter_self_enrolled", g.user.id, voter_id=v.id)
    return jsonify(_view(v))


@bp.put("/me/address")
@role_required("voter")
@recent_auth_required
def update_address():
    v = _my_voter()
    v.address = _text(request.get_json(silent=True) or {}, "address", 5, 200)
    db.session.commit()
    audit.record("address_changed", g.user.id, voter_id=v.id, fields=["address"])
    return jsonify(_view(v))


@bp.get("/voters")
@role_required("enrolment_officer")
def list_voters():
    division = request.args.get("division")
    q = db.session.query(Voter, User.email).join(User, User.id == Voter.user_id)
    if division:
        q = q.filter(Voter.division == division)
    rows = q.order_by(Voter.id).limit(200).all()
    audit.record("pii_read", g.user.id, division=division, records=len(rows))
    return jsonify(voters=[_view(v, email) for v, email in rows])


@bp.post("/voters")
@role_required("enrolment_officer")
@recent_auth_required
def register():
    data = request.get_json(silent=True) or {}
    email = _text(data, "email", 6, 254).lower()
    if not EMAIL.match(email):
        abort(400, description="email is not valid")
    division = _text(data, "division", 2, 64)
    if not DIVISION.match(division):
        abort(400, description="division is not valid")
    d, age = _dob(data)
    if age < VOTING_AGE:
        abort(403, description="must be 18 or older to enrol to vote")
    if User.query.filter_by(email=email).first():
        abort(409, description="an account with this email already exists")

    temp_password = secrets.token_urlsafe(12)  # handed to the citizen once, out of band
    user = User(email=email, password_hash=hash_password(temp_password), role="voter")
    db.session.add(user)
    db.session.flush()
    v = Voter(user_id=user.id, full_name=_text(data, "full_name", 2, 200), date_of_birth=d.isoformat(),
              address=_text(data, "address", 5, 200), division=division, enrolled=True)
    db.session.add(v)
    db.session.commit()
    audit.record("voter_registered", g.user.id, voter_id=v.id, division=division)
    return jsonify(voter=_view(v, email), temporary_password=temp_password), 201
