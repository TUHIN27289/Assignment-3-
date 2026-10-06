"""Ballot validation (base version, SR-11 owner extends this).

House of Representatives: every box must be numbered, so the preference
list has to contain each candidate in the voter's division exactly once.
Senate validation (above/below the line) is still to be added.
"""
from ..models import Candidate


class InvalidBallot(ValueError):
    pass


def validate_ballot(ballot, division):
    if not isinstance(ballot, dict) or set(ballot) - {"house", "senate"}:
        raise InvalidBallot("unexpected ballot structure")
    house = ballot.get("house")
    if not isinstance(house, list) or not all(isinstance(c, int) for c in house):
        raise InvalidBallot("house preferences must be a list of candidate ids")
    expected = {c.id for c in Candidate.query.filter_by(division=division)}
    if len(house) != len(expected) or set(house) != expected:
        raise InvalidBallot("house ballot must number every candidate exactly once")
    return {"house": house}
