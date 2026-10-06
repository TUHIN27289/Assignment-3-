"""SR-13: ballots are encrypted at submission and never stored in plaintext."""
import json

import pytest
from cryptography.exceptions import InvalidTag

from app.ballot.crypto import EncryptedBallot, decrypt_ballot, encrypt_ballot
from app.extensions import db
from app.keys import KeyService
from app.models import CastBallot

from .conftest import candidate_ids, vote

BALLOT = {"house": [3, 1, 4, 2]}


@pytest.fixture
def keys(tmp_path):
    return KeyService(str(tmp_path / "k"))


def test_round_trip(keys):
    enc = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    assert decrypt_ballot(enc, keys.ballot_private_key(), "b-1") == BALLOT


def test_same_ballot_encrypts_differently_each_time(keys):
    a = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    b = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    assert a.ciphertext != b.ciphertext and a.wrapped_key != b.wrapped_key


def test_tampered_ciphertext_is_rejected(keys):
    enc = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    flipped = bytes([enc.ciphertext[0] ^ 1]) + enc.ciphertext[1:]
    with pytest.raises(InvalidTag):
        decrypt_ballot(EncryptedBallot(flipped, enc.nonce, enc.wrapped_key), keys.ballot_private_key(), "b-1")


def test_ciphertext_moved_to_another_ballot_id_is_rejected(keys):
    enc = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    with pytest.raises(InvalidTag):
        decrypt_ballot(enc, keys.ballot_private_key(), "b-2")


def test_other_private_key_cannot_decrypt(keys, tmp_path):
    other = KeyService(str(tmp_path / "other"))
    enc = encrypt_ballot(BALLOT, keys.ballot_public_key(), "b-1")
    with pytest.raises(ValueError):
        decrypt_ballot(enc, other.ballot_private_key(), "b-1")


def test_stored_ballot_contains_no_plaintext(app, client):
    prefs = candidate_ids(app)
    assert vote(app, client, "voter1@test.local", prefs).status_code == 200
    with app.app_context():
        row = CastBallot.query.one()
        stored = row.ciphertext + row.nonce + row.wrapped_key
        assert json.dumps(prefs).encode() not in stored
        assert b"house" not in stored


def test_voting_path_never_loads_private_key(app, client, monkeypatch):
    def forbidden(self):
        raise AssertionError("private key used on the voting path")
    monkeypatch.setattr(KeyService, "ballot_private_key", forbidden)
    assert vote(app, client, "voter1@test.local").status_code == 200


def test_private_key_file_permissions(keys):
    import os, stat
    mode = stat.S_IMODE(os.stat(os.path.join(keys.key_dir, "ballot_private.pem")).st_mode)
    assert mode == 0o600
