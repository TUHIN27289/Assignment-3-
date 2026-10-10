"""Key service (SR-20: key management).

Each purpose gets its own key:
  - ballot encryption key pair (RSA-3072). The ballot service only ever
    loads the PUBLIC key. The private key is loaded by the tally only.
  - ballot integrity key (256-bit HMAC key) for the hash chain.
  - audit key (256-bit HMAC key) for the audit log chain (SR-04).
  - MFA key (256-bit AES key) that encrypts users' TOTP secrets (SR-01).

Keys are generated on first run for development and kept in KEY_DIR, which
sits outside the repo. In production these would live in an HSM.

SR-20 rules enforced here:
  - one key per purpose, never reused across purposes
  - no key material in the source tree (a test scans the repo for it)
  - private keys encrypted at rest when KEY_PASSPHRASE is set
  - the app refuses to start if the key folder or files are readable by
    other users (folder 0700, files 0600)
  - signing keys are versioned and can be rotated. Old public keys are kept,
    so anything signed before a rotation can still be verified. Every
    signature carries a key id (kid) saying which key made it.
"""
import hashlib
import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


class KeyPermissionError(RuntimeError):
    pass


def fingerprint(public_key):
    """Short, stable id for a public key: first 16 hex chars of SHA-256 over its DER."""
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


class KeyService:
    SIGNING_PURPOSES = ("results",)

    def __init__(self, key_dir, passphrase=None):
        self.key_dir = key_dir
        self._passphrase = passphrase.encode() if passphrase else None
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        for purpose in self.SIGNING_PURPOSES:
            if not self._versions(purpose):
                self.rotate(purpose)
        self._ensure_ballot_keypair()
        self._ensure_integrity_key()
        self._ensure_secret("audit.key")
        self._ensure_secret("mfa.key")

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
        self._write_secret("ballot_private.pem", self._private_pem(private_key))
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

    def mfa_key(self):
        with open(self._path("mfa.key"), "rb") as f:
            return f.read()

    def audit_key(self):
        with open(self._path("audit.key"), "rb") as f:
            return f.read()

    def ballot_public_key(self):
        with open(self._path("ballot_public.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def ballot_private_key(self):
        """Tally only. Nothing on the voting path should call this."""
        with open(self._path("ballot_private.pem"), "rb") as f:
            return self._load_private(f.read())

    def integrity_key(self):
        with open(self._path("ballot_integrity.key"), "rb") as f:
            return f.read()

    # ---- SR-20 ----

    def _private_pem(self, key):
        enc = (serialization.BestAvailableEncryption(self._passphrase)
               if self._passphrase else serialization.NoEncryption())
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)

    def _load_private(self, data):
        return serialization.load_pem_private_key(data, password=self._passphrase)

    def check_permissions(self):
        """Raise if the key folder or any key file is open to other users."""
        if os.name == "nt": # Skip on Windows: it uses ACLs, not Unix permission bits
            return
        problems = []
        for root, dirs, files in os.walk(self.key_dir):
            if stat.S_IMODE(os.stat(root).st_mode) & 0o077:
                problems.append(f"{root} is readable by others (should be 0700)")
            for name in files:
                path = os.path.join(root, name)
                if name.endswith((".pem", ".key")) and "public" not in name and not name.startswith("pub-"):
                    if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
                        problems.append(f"{path} is readable by others (should be 0600)")
        if problems:
            raise KeyPermissionError("; ".join(problems))

    # versioned signing keys: KEY_DIR/signing/<purpose>/v<N>.pem (+ pub-v<N>.pem)

    def _signing_dir(self, purpose):
        if purpose not in self.SIGNING_PURPOSES:
            raise ValueError(f"unknown signing purpose {purpose}")
        d = os.path.join(self.key_dir, "signing", purpose)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(os.path.join(self.key_dir, "signing"), 0o700)
        return d

    def _versions(self, purpose):
        d = self._signing_dir(purpose)
        return sorted(int(n[1:-4]) for n in os.listdir(d) if n.startswith("v") and n.endswith(".pem"))

    def rotate(self, purpose):
        """Create a new signing key version and make it current. Returns its kid."""
        d = self._signing_dir(purpose)
        version = (self._versions(purpose) or [0])[-1] + 1
        key = ed25519.Ed25519PrivateKey.generate()
        fd = os.open(os.path.join(d, f"v{version}.pem"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(self._private_pem(key))
        with open(os.path.join(d, f"pub-v{version}.pem"), "wb") as f:
            f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
        return fingerprint(key.public_key())

    def signing_key(self, purpose):
        """Current (newest) signing key for a purpose, as (kid, private_key)."""
        version = self._versions(purpose)[-1]
        with open(os.path.join(self._signing_dir(purpose), f"v{version}.pem"), "rb") as f:
            key = self._load_private(f.read())
        return fingerprint(key.public_key()), key

    def public_keys(self, purpose):
        """All public keys ever used for a purpose, {kid: pem}. Old ones stay for verification."""
        d, out = self._signing_dir(purpose), {}
        for v in self._versions(purpose):
            with open(os.path.join(d, f"pub-v{v}.pem"), "rb") as f:
                pem = f.read()
            out[fingerprint(serialization.load_pem_public_key(pem))] = pem.decode()
        return out

    def fingerprints(self):
        """Public fingerprints auditors can compare against the key ceremony record."""
        return {
            "ballot_encryption": fingerprint(self.ballot_public_key()),
            **{f"{p}_signing": list(self.public_keys(p)) for p in self.SIGNING_PURPOSES},
        }
