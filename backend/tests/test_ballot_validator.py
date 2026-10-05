import pytest
from app.validators import BallotValidator

def test_valid_ballot_structure():
    """Test 1: Valid ballot payload passes structural validation."""
    valid_payload = {
        "election_id": "ELEC-2026-01",
        "preferences": [
            {"candidate_id": "CAND-101", "rank": 1},
            {"candidate_id": "CAND-102", "rank": 2},
            {"candidate_id": "CAND-103", "rank": 3}
        ]
    }
    result = BallotValidator.validate_ballot_structure(valid_payload)
    assert result["is_valid"] is True
    assert len(result["errors"]) == 0
    assert result["cleaned_data"]["election_id"] == "ELEC-2026-01"
    assert len(result["cleaned_data"]["preferences"]) == 3

def test_null_and_non_dict_payload():
    """Test 2: Null or non-dictionary input is rejected."""
    assert BallotValidator.validate_ballot_structure(None)["is_valid"] is False
    assert BallotValidator.validate_ballot_structure("raw-string")["is_valid"] is False
    assert BallotValidator.validate_ballot_structure([1, 2, 3])["is_valid"] is False
    assert BallotValidator.validate_ballot_structure(12345)["is_valid"] is False

def test_missing_required_fields():
    """Test 3: Missing election_id or preferences is rejected."""
    # Missing election_id
    payload1 = {"preferences": [{"candidate_id": "CAND-1", "rank": 1}]}
    res1 = BallotValidator.validate_ballot_structure(payload1)
    assert res1["is_valid"] is False
    assert any("election_id" in err for err in res1["errors"])

    # Missing preferences
    payload2 = {"election_id": "ELEC-2026-01"}
    res2 = BallotValidator.validate_ballot_structure(payload2)
    assert res2["is_valid"] is False
    assert any("preferences" in err for err in res2["errors"])

def test_empty_input_rejection():
    """Test 4: Empty string election_id or empty preferences list is rejected."""
    # Empty election_id
    payload1 = {"election_id": "   ", "preferences": [{"candidate_id": "CAND-1", "rank": 1}]}
    res1 = BallotValidator.validate_ballot_structure(payload1)
    assert res1["is_valid"] is False

    # Empty preferences list
    payload2 = {"election_id": "ELEC-2026-01", "preferences": []}
    res2 = BallotValidator.validate_ballot_structure(payload2)
    assert res2["is_valid"] is False

def test_invalid_field_data_types():
    """Test 5: Wrong data types for election_id or preferences list are rejected."""
    # Non-string election_id
    payload1 = {"election_id": 12345, "preferences": [{"candidate_id": "CAND-1", "rank": 1}]}
    assert BallotValidator.validate_ballot_structure(payload1)["is_valid"] is False

    # Non-list preferences
    payload2 = {"election_id": "ELEC-2026-01", "preferences": "single-preference-string"}
    assert BallotValidator.validate_ballot_structure(payload2)["is_valid"] is False

def test_malformed_preference_items():
    """Test 6: Malformed individual preference items are rejected."""
    # Non-dict item in preferences
    payload1 = {"election_id": "ELEC-1", "preferences": ["not-a-dict"]}
    assert BallotValidator.validate_ballot_structure(payload1)["is_valid"] is False

    # Null item in preferences
    payload2 = {"election_id": "ELEC-1", "preferences": [None]}
    assert BallotValidator.validate_ballot_structure(payload2)["is_valid"] is False

    # Missing candidate_id
    payload3 = {"election_id": "ELEC-1", "preferences": [{"rank": 1}]}
    assert BallotValidator.validate_ballot_structure(payload3)["is_valid"] is False

    # Non-string candidate_id
    payload4 = {"election_id": "ELEC-1", "preferences": [{"candidate_id": 999, "rank": 1}]}
    assert BallotValidator.validate_ballot_structure(payload4)["is_valid"] is False

    # Missing rank
    payload5 = {"election_id": "ELEC-1", "preferences": [{"candidate_id": "CAND-1"}]}
    assert BallotValidator.validate_ballot_structure(payload5)["is_valid"] is False

    # Non-integer rank (string, float, bool)
    payload6a = {"election_id": "ELEC-1", "preferences": [{"candidate_id": "CAND-1", "rank": "1"}]}
    assert BallotValidator.validate_ballot_structure(payload6a)["is_valid"] is False

    payload6b = {"election_id": "ELEC-1", "preferences": [{"candidate_id": "CAND-1", "rank": 1.5}]}
    assert BallotValidator.validate_ballot_structure(payload6b)["is_valid"] is False

    payload6c = {"election_id": "ELEC-1", "preferences": [{"candidate_id": "CAND-1", "rank": True}]}
    assert BallotValidator.validate_ballot_structure(payload6c)["is_valid"] is False

    # Rank < 1
    payload7 = {"election_id": "ELEC-1", "preferences": [{"candidate_id": "CAND-1", "rank": 0}]}
    assert BallotValidator.validate_ballot_structure(payload7)["is_valid"] is False

def test_cleaned_data_normalizes_whitespace():
    """Test 7: Cleaned data trims leading/trailing whitespace."""
    payload = {
        "election_id": "  ELEC-2026-01  ",
        "preferences": [
            {"candidate_id": "  CAND-101  ", "rank": 1}
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is True
    assert res["cleaned_data"]["election_id"] == "ELEC-2026-01"
    assert res["cleaned_data"]["preferences"][0]["candidate_id"] == "CAND-101"
