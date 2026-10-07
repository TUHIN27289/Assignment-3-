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
        db.session.add(Voter(user_id=u.id, full_name=f"Demo Voter {n}", date_of_birth=f"19{80 + n}-0{n}-1{n}",
                             address=f"{n} Swanston St, Melbourne VIC 3000", division="Melbourne", enrolled=True))
    for role in ("enrolment_officer", "delegate", "tally_officer", "auditor"):
        db.session.add(User(email=f"{role}@demo.local", password_hash=hash_password(DEMO_PASSWORD), role=role))
    db.session.commit()
    print("seeded demo accounts (see seed.py for the password)")
