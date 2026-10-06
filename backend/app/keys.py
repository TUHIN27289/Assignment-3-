"""Key service (base version, SR-20 owner extends this).

Each purpose gets its own key:
  - ballot encryption key pair (RSA-3072). The ballot service only ever
    loads the PUBLIC key. The private key is loaded by the tally only.
  - ballot integrity key (256-bit HMAC key) for the hash chain.
  - audit key (256-bit HMAC key) for the audit log chain (SR-04).

Keys are generated on first run for development and kept in KEY_DIR, which
sits outside the repo. In production these would live in an HSM.
"""
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyService:
    def __init__(self, key_dir):
        self.key_dir = key_dir
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        self._ensure_ballot_keypair()
        self._ensure_integrity_key()
        self._ensure_secret("audit.key")

    def _path(self, name):
        return os.path.join(self.key_dir, name)

    def _write_secret(self, name, data):
        fd = os.open(self._path(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    def _ensure_ballot_keypair(self):
        if os.path.exists(self._path("ballot_private.pem")):
            return
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self._write_secret("ballot_private.pem", private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        with open(self._path("ballot_public.pem"), "wb") as f:
            f.write(private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def _ensure_integrity_key(self):
        if not os.path.exists(self._path("ballot_integrity.key")):
            self._write_secret("ballot_integrity.key", os.urandom(32))

    def _ensure_secret(self, name):
        if not os.path.exists(self._path(name)):
            self._write_secret(name, os.urandom(32))

    def audit_key(self):
        with open(self._path("audit.key"), "rb") as f:
            return f.read()

    def ballot_public_key(self):
        with open(self._path("ballot_public.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def ballot_private_key(self):
        """Tally only. Nothing on the voting path should call this."""
        with open(self._path("ballot_private.pem"), "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def integrity_key(self):
        with open(self._path("ballot_integrity.key"), "rb") as f:
            return f.read()
