"""Ballot cryptography.

SR-13  Ballot encryption (envelope encryption)
  Each ballot gets a fresh random AES-256 key. The ballot is encrypted with
  AES-GCM and that key is then wrapped (encrypted) with the tally's RSA-OAEP
  public key. The ballot service only has the public key, so once a ballot
  is stored even the voting server can't read it back. Only the tally,
  holding the private key, can unwrap the AES key and decrypt.
  The ballot_id is bound in as associated data, so a ciphertext copied onto
  another ballot's row fails to decrypt.

SR-15  Ballot integrity
  digest    = SHA-256 over the stored fields of one ballot
  chain_mac = HMAC-SHA256(integrity_key, previous chain_mac + digest)
  Editing, deleting, inserting or reordering any stored ballot breaks the
  chain from that point, and without the integrity key an attacker with
  database access can't rebuild a valid chain.
"""
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GENESIS_MAC = "0" * 64

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


@dataclass
class EncryptedBallot:
    ciphertext: bytes
    nonce: bytes
    wrapped_key: bytes


def _canonical(ballot):
    return json.dumps(ballot, sort_keys=True, separators=(",", ":")).encode()


def encrypt_ballot(ballot, public_key, ballot_id):
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, _canonical(ballot), ballot_id.encode())
    wrapped_key = public_key.encrypt(data_key, _OAEP)
    return EncryptedBallot(ciphertext, nonce, wrapped_key)


def decrypt_ballot(enc, private_key, ballot_id):
    data_key = private_key.decrypt(enc.wrapped_key, _OAEP)
    plaintext = AESGCM(data_key).decrypt(enc.nonce, enc.ciphertext, ballot_id.encode())
    return json.loads(plaintext)


def ballot_digest(ballot_id, election_id, division, enc):
    h = hashlib.sha256()
    # length-prefix each field so two different field splits can't hash the same
    for part in (ballot_id.encode(), election_id.encode(), division.encode(),
                 enc.nonce, enc.wrapped_key, enc.ciphertext):
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return h.hexdigest()


def chain_mac(integrity_key, prev_mac, digest):
    return hmac.new(integrity_key, (prev_mac + digest).encode(), hashlib.sha256).hexdigest()


def sign_receipt(receipt_key, tracking_code):
    """SR-10: computes HMAC-SHA256 signature over the tracking code."""
    return hmac.new(receipt_key, tracking_code.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_receipt(receipt_key, tracking_code, signature):
    """SR-10: verifies the cryptographic receipt signature."""
    expected = hmac.new(receipt_key, tracking_code.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

