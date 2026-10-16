"""SR-05: voter personal data encrypted at rest.

Name, date of birth and address are encrypted field by field with
AES-256-GCM before they reach the database, and decrypted when read back.
It's done in a column type, so the rest of the code just sees strings.

  stored = b"v1" + 12-byte random nonce + ciphertext (with GCM tag)
  associated data = "<table>.<column>", so a value copied into another
  column (e.g. a name pasted into the address field) fails to decrypt

Someone who steals the database file or a backup gets ciphertext only.
The key lives in the key service (SR-20), not in the database.
The "v1" prefix leaves room for key rotation later.

Not encrypted: email (it's the login identifier, needed for lookups) and
division (needed to count votes and not identifying on its own).
Encrypted fields can't be searched or sorted in SQL, which is fine here.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app
from sqlalchemy import LargeBinary
from sqlalchemy.types import TypeDecorator

VERSION = b"v1"


def _aesgcm():
    return AESGCM(current_app.extensions["keys"].pii_key())


class EncryptedText(TypeDecorator):
    impl = LargeBinary
    cache_ok = True

    def __init__(self, field):
        super().__init__()
        self.field = field  # e.g. "voters.full_name", used as associated data

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        nonce = os.urandom(12)
        return VERSION + nonce + _aesgcm().encrypt(nonce, str(value).encode(), self.field.encode())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value[:2] != VERSION:
            raise ValueError(f"unknown encryption version for {self.field}")
        nonce, ct = value[2:14], value[14:]
        return _aesgcm().decrypt(nonce, ct, self.field.encode()).decode()
