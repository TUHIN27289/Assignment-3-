import pytest
from app.validators import BallotValidator

# --- Step 1 Regression Tests ---

def test_valid_ballot_structure():
    """Test 1: Valid ballot payload passes structural and order validation."""
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
    payload1 = {"election_id": "   ", "preferences": [{"candidate_id": "CAND-1", "rank": 1}]}
    res1 = BallotValidator.validate_ballot_structure(payload1)
    assert res1["is_valid"] is False

    payload2 = {"election_id": "ELEC-2026-01", "preferences": []}
    res2 = BallotValidator.validate_ballot_structure(payload2)
    assert res2["is_valid"] is False

def test_invalid_field_data_types():
    """Test 5: Wrong data types for election_id or preferences list are rejected."""
    payload1 = {"election_id": 12345, "preferences": [{"candidate_id": "CAND-1", "rank": 1}]}
    assert BallotValidator.validate_ballot_structure(payload1)["is_valid"] is False

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


# --- Step 2 Preference-Order Business Rule Tests ---

def test_valid_unordered_input_sorted_in_cleaned_data():
    """Test 7: Unordered preference input list with valid ranks [3, 1, 2] is accepted and sorted in cleaned_data."""
    payload = {
        "election_id": "ELEC-2026-01",
        "preferences": [
            {"candidate_id": "CAND-C", "rank": 3},
            {"candidate_id": "CAND-A", "rank": 1},
            {"candidate_id": "CAND-B", "rank": 2}
        ]
    }
    result = BallotValidator.validate_ballot_structure(payload)
    assert result["is_valid"] is True

    cleaned = result["cleaned_data"]["preferences"]
    assert cleaned[0]["candidate_id"] == "CAND-A"
    assert cleaned[0]["rank"] == 1
    assert cleaned[1]["candidate_id"] == "CAND-B"
    assert cleaned[1]["rank"] == 2
    assert cleaned[2]["candidate_id"] == "CAND-C"
    assert cleaned[2]["rank"] == 3

def test_duplicate_candidate_id_rejected():
    """Test 8: Rejects payload where the same candidate appears more than once."""
    payload = {
        "election_id": "ELEC-1",
        "preferences": [
            {"candidate_id": "CAND-101", "rank": 1},
            {"candidate_id": "CAND-101", "rank": 2}
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is False
    assert any("Duplicate candidate ID 'CAND-101'" in err for err in res["errors"])

def test_duplicate_rank_rejected():
    """Test 9: Rejects payload where two candidates are assigned the same rank."""
    payload = {
        "election_id": "ELEC-1",
        "preferences": [
            {"candidate_id": "CAND-101", "rank": 1},
            {"candidate_id": "CAND-102", "rank": 1}
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is False
    assert any("Duplicate rank '1'" in err for err in res["errors"])

@pytest.mark.parametrize("invalid_ranks, expected_error_snippet", [
    ([2, 3, 4], "must start at 1. Smallest rank found was 2"),
    ([0, 1, 2], "must be a positive integer >= 1"),
    ([1, 2, 4], "continuous sequence starting at 1. Missing rank 3"),
    ([1, 3, 4], "continuous sequence starting at 1. Missing rank 2"),
    ([1, 2, 5], "continuous sequence starting at 1. Missing rank 3"),
])
def test_invalid_rank_sequences_rejected(invalid_ranks, expected_error_snippet):
    """Test 10: Parameterized test verifying rank sequence gap, invalid starting rank, and non-continuous sequence rejections."""
    payload = {
        "election_id": "ELEC-1",
        "preferences": [
            {"candidate_id": f"CAND-{r}", "rank": r} for r in invalid_ranks
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is False
    assert any(expected_error_snippet in err for err in res["errors"])

def test_multiple_invalid_conditions():
    """Test 11: Rejects payload with multiple ordering violations (duplicate candidates AND duplicate ranks)."""
    payload = {
        "election_id": "ELEC-1",
        "preferences": [
            {"candidate_id": "CAND-101", "rank": 1},
            {"candidate_id": "CAND-101", "rank": 1}
        ]
    }
    res = BallotValidator.validate_ballot_structure(payload)
    assert res["is_valid"] is False
    assert any("Duplicate candidate ID" in err for err in res["errors"])
    assert any("Duplicate rank" in err for err in res["errors"])
