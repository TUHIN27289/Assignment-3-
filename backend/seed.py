"""Demo data for local development. These accounts are test values only."""
from app import create_app
from app.auth import hash_password
from app.extensions import db
from app.models import Candidate, User, Voter

DEMO_PASSWORD = "Demo-Only-2026!"

app = create_app()
with app.app_context():
    if User.query.first():
        print("already seeded")
        raise SystemExit
    for i, (name, party) in enumerate([("A. Adams", "Party A"), ("B. Brown", "Party B"),
                                        ("C. Chen", "Party C"), ("D. Davis", "Independent")], start=1):
        db.session.add(Candidate(name=name, party=party, division="Melbourne", ballot_order=i))
    for n in range(1, 6):
        u = User(email=f"voter{n}@demo.local", password_hash=hash_password(DEMO_PASSWORD), role="voter")
        db.session.add(u)
        db.session.flush()
        db.session.add(Voter(user_id=u.id, full_name=f"Demo Voter {n}", division="Melbourne", enrolled=True))
    for role in ("enrolment_officer", "delegate", "tally_officer", "auditor"):
        db.session.add(User(email=f"{role}@demo.local", password_hash=hash_password(DEMO_PASSWORD), role=role,
                            state="VIC" if role == "delegate" else None))
    # SR-17 needs a second delegate to approve changes
    db.session.add(User(email="delegate2@demo.local", password_hash=hash_password(DEMO_PASSWORD),
                        role="delegate", state="VIC"))
    db.session.commit()
    print("seeded demo accounts (see seed.py for the password)")
