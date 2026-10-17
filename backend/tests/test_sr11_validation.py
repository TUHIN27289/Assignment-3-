"""SR-11: Server-side ballot and input validation.

Verifies candidate preference ordering, structure validation, and business rules:
- No duplicate candidate IDs.
- No duplicate ranks.
- Ranks must start at 1 and form a contiguous sequence without gaps.
- Full preferential voting for House of Representatives.
- Above/below the line rules for Senate contests.
- Failed validation keeps token valid for resubmission.
"""
import pytest
from app.ballot.validation import InvalidBallot, validate_ballot
from app.validators import BallotValidator
from .conftest import csrf, login, candidate_ids


def test_valid_house_ballot_list_format(app):
    """List of candidate IDs covering all candidates in the division is valid."""
    with app.app_context():
        res = validate_ballot({"house": [1, 2, 3, 4]}, "Melbourne")
        assert res["house"] == [1, 2, 3, 4]


def test_valid_house_ballot_ranked_objects(app):
    """Ranked objects format [{'candidate_id': 1, 'rank': 1}, ...] is valid."""
    with app.app_context():
        raw = [
            {"candidate_id": 3, "rank": 1},
            {"candidate_id": 1, "rank": 2},
            {"candidate_id": 4, "rank": 3},
            {"candidate_id": 2, "rank": 4},
        ]
        res = validate_ballot({"house": raw}, "Melbourne")
        assert res["house"] == [3, 1, 4, 2]


def test_house_duplicate_candidate_rejected(app):
    """Duplicate candidate IDs in House preferences are rejected."""
    with app.app_context():
        with pytest.raises(InvalidBallot, match="duplicate candidate"):
            validate_ballot({"house": [1, 1, 3, 4]}, "Melbourne")


def test_house_incomplete_candidates_rejected(app):
    """Full preferential voting requires all candidates to be numbered."""
    with app.app_context():
        with pytest.raises(InvalidBallot, match="number every candidate"):
            validate_ballot({"house": [1, 2, 3]}, "Melbourne")


def test_house_wrong_division_candidate_rejected(app):
    """Candidates outside the voter's division are rejected."""
    with app.app_context():
        with pytest.raises(InvalidBallot, match="number every candidate"):
            validate_ballot({"house": [1, 2, 3, 999]}, "Melbourne")


def test_house_rank_gap_rejected(app):
    """Gaps in ranking sequence (e.g. ranks 1, 2, 4) are rejected."""
    with app.app_context():
        raw = [
            {"candidate_id": 1, "rank": 1},
            {"candidate_id": 2, "rank": 2},
            {"candidate_id": 3, "rank": 4},
            {"candidate_id": 4, "rank": 5},
        ]
        with pytest.raises(InvalidBallot, match="contiguous without gaps"):
            validate_ballot({"house": raw}, "Melbourne")


def test_house_rank_not_starting_at_one_rejected(app):
    """Preferences not starting at rank 1 are rejected."""
    with app.app_context():
        raw = [
            {"candidate_id": 1, "rank": 2},
            {"candidate_id": 2, "rank": 3},
            {"candidate_id": 3, "rank": 4},
            {"candidate_id": 4, "rank": 5},
        ]
        with pytest.raises(InvalidBallot, match="must start at rank 1"):
            validate_ballot({"house": raw}, "Melbourne")


def test_senate_above_the_line_validation(app):
    """Senate above-the-line requires at least 6 unique party preferences."""
    with app.app_context():
        # Valid: 6 parties
        res = validate_ballot({"senate": {"above_the_line": [10, 11, 12, 13, 14, 15]}}, "Melbourne")
        assert res["senate"]["above_the_line"] == [10, 11, 12, 13, 14, 15]

        # Too few (< 6)
        with pytest.raises(InvalidBallot, match="at least 6"):
            validate_ballot({"senate": {"above_the_line": [10, 11, 12, 13, 14]}}, "Melbourne")

        # Duplicate party
        with pytest.raises(InvalidBallot, match="duplicate party"):
            validate_ballot({"senate": {"above_the_line": [10, 11, 12, 13, 14, 10]}}, "Melbourne")


def test_senate_below_the_line_validation(app):
    """Senate below-the-line requires at least 12 unique candidate preferences."""
    with app.app_context():
        # Valid: 12 candidates
        res = validate_ballot({"senate": {"below_the_line": list(range(1, 13))}}, "Melbourne")
        assert len(res["senate"]["below_the_line"]) == 12

        # Too few (< 12)
        with pytest.raises(InvalidBallot, match="at least 12"):
            validate_ballot({"senate": {"below_the_line": list(range(1, 12))}}, "Melbourne")

        # Duplicates
        with pytest.raises(InvalidBallot, match="duplicate candidate"):
            validate_ballot({"senate": {"below_the_line": [1] * 12}}, "Melbourne")


def test_invalid_ballot_keeps_token_usable_for_correction(app, client):
    """Submitting an invalid ballot does not consume the token, allowing correction."""
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]

    anon = app.test_client()
    h = {"X-CSRF-Token": csrf(anon)}

    # Submit invalid ballot (only 1 candidate)
    bad_res = anon.post("/api/ballot/cast", json={"ballot_token": token, "ballot": {"house": [1]}}, headers=h)
    assert bad_res.status_code == 400

    # Resubmit with corrected valid ballot using the SAME token
    good_res = anon.post("/api/ballot/cast", json={"ballot_token": token, "ballot": {"house": [1, 2, 3, 4]}}, headers=h)
    assert good_res.status_code == 200
    assert "tracking_code" in good_res.get_json()


def test_ballot_validator_utility():
    """Validates structural and preference order rules via BallotValidator utility."""
    # Valid
    payload = {
        "election_id": "federal-2026",
        "preferences": [
            {"candidate_id": "C-1", "rank": 2},
            {"candidate_id": "C-2", "rank": 1},
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is True
    assert res["cleaned_data"]["preferences"][0]["candidate_id"] == "C-2"

    # Gaps in ranking
    bad_gap = {
        "election_id": "federal-2026",
        "preferences": [
            {"candidate_id": "C-1", "rank": 1},
            {"candidate_id": "C-2", "rank": 3},
        ]
    }
    assert BallotValidator.validate_ballot_structure(bad_gap)["is_valid"] is False

    # Duplicates
    bad_dup = {
        "election_id": "federal-2026",
        "preferences": [
            {"candidate_id": "C-1", "rank": 1},
            {"candidate_id": "C-1", "rank": 2},
        ]
    }
    assert BallotValidator.validate_ballot_structure(bad_dup)["is_valid"] is False
