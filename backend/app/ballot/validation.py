"""SR-11: Server-side ballot and input validation.

Validates preferential ballot structure and candidate ordering business rules:
- Validates structure and types safely.
- All candidate IDs must be valid integers and belong to the voter's division.
- Rejects duplicate candidates.
- Rejects duplicate ranks or gaps in sequential preference ordering.
- For House of Representatives, full preferential voting is enforced:
  every candidate in the division must be numbered exactly once.
- For Senate (if provided), validates above-the-line (minimum 6 parties/groups)
  or below-the-line (minimum 12 candidates) preferences without duplicates.
"""
from ..models import Candidate


class InvalidBallot(ValueError):
    pass


def _validate_house_list(house, expected_candidate_ids):
    if not isinstance(house, list):
        raise InvalidBallot("house preferences must be a list")
    if not house:
        raise InvalidBallot("house ballot cannot be empty")

    # Support either list of candidate IDs [id1, id2, ...] OR list of dicts [{"candidate_id": ..., "rank": ...}]
    if all(isinstance(c, int) for c in house):
        candidate_ids = house
        # Check duplicates
        if len(candidate_ids) != len(set(candidate_ids)):
            raise InvalidBallot("duplicate candidate in house preferences")
    elif all(isinstance(c, dict) for c in house):
        # Structured preference objects
        candidate_ids = []
        ranks = []
        for pref in house:
            cid = pref.get("candidate_id")
            rank = pref.get("rank")
            if not isinstance(cid, int) or not isinstance(rank, int):
                raise InvalidBallot("candidate_id and rank must be integers")
            candidate_ids.append(cid)
            ranks.append(rank)

        # Check candidate uniqueness
        if len(candidate_ids) != len(set(candidate_ids)):
            raise InvalidBallot("duplicate candidate in house preferences")

        # Check rank uniqueness and contiguous 1..N sequence
        sorted_ranks = sorted(ranks)
        if sorted_ranks[0] != 1:
            raise InvalidBallot("preferences must start at rank 1")
        for i, r in enumerate(sorted_ranks, start=1):
            if r != i:
                raise InvalidBallot("preference ranks must be contiguous without gaps or duplicates")

        # Sort candidate IDs by rank order
        ordered = [cid for _, cid in sorted(zip(ranks, candidate_ids))]
        candidate_ids = ordered
    else:
        raise InvalidBallot("house preferences must be candidate ids or ranked preference objects")

    # Verify all candidates belong to the division and match full preferential rule
    candidate_set = set(candidate_ids)
    if candidate_set != expected_candidate_ids or len(candidate_ids) != len(expected_candidate_ids):
        raise InvalidBallot("house ballot must number every candidate in division exactly once")

    return candidate_ids


def _validate_senate(senate):
    if not isinstance(senate, dict) or not ({"above_the_line", "below_the_line"} & set(senate)):
        raise InvalidBallot("senate ballot must specify above_the_line or below_the_line")

    atl = senate.get("above_the_line")
    btl = senate.get("below_the_line")

    if atl is not None:
        if not isinstance(atl, list) or not all(isinstance(p, int) for p in atl):
            raise InvalidBallot("above_the_line must be a list of party/group ids")
        if len(atl) < 6:
            raise InvalidBallot("above-the-line voting requires numbering at least 6 parties/groups")
        if len(atl) != len(set(atl)):
            raise InvalidBallot("duplicate party/group in above-the-line preferences")
        return {"above_the_line": atl}

    if btl is not None:
        if not isinstance(btl, list) or not all(isinstance(c, int) for c in btl):
            raise InvalidBallot("below_the_line must be a list of candidate ids")
        if len(btl) < 12:
            raise InvalidBallot("below-the-line voting requires numbering at least 12 candidates")
        if len(btl) != len(set(btl)):
            raise InvalidBallot("duplicate candidate in below-the-line preferences")
        return {"below_the_line": btl}

    raise InvalidBallot("invalid senate ballot specification")


def validate_ballot(ballot, division):
    if not isinstance(ballot, dict) or not ballot:
        raise InvalidBallot("unexpected ballot structure")
    if set(ballot) - {"house", "senate"}:
        raise InvalidBallot("unexpected ballot structure: unknown contest type")

    result = {}

    if "house" in ballot:
        expected = {c.id for c in Candidate.query.filter_by(division=division)}
        result["house"] = _validate_house_list(ballot["house"], expected)

    if "senate" in ballot:
        result["senate"] = _validate_senate(ballot["senate"])

    if not result:
        raise InvalidBallot("ballot must contain at least house or senate contest")

    return result
