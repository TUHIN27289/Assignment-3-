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
  - private keys encrypted at rest when KEY_PASSPHRASE is set. The passphrase
    is required when APP_ENV=production, so keys are never in the clear there
  - the 256-bit secrets (audit, MFA, integrity) are encrypted at rest too,
    with AES-256-GCM under a key derived from the passphrase (scrypt). The
    file name is bound in as associated data, so a secret copied into the
    wrong file is rejected instead of being used for the wrong purpose
  - the app refuses to start if the key folder or files are readable by
    other users (folder 0700, files 0600)
  - signing keys are versioned and can be rotated. Old public keys are kept,
    so anything signed before a rotation can still be verified, and old
    private keys are deleted, so only the current key can sign. Every
    signature carries a key id (kid) saying which key made it. Every
    rotation is written to the audit log (SR-04).
"""
import hashlib
import os
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Header for an encrypted secret file: magic | salt (16) | nonce (12) | ciphertext
SECRET_MAGIC = b"EVP-KEY1"
SCRYPT_N = 2 ** 15
MIN_PASSPHRASE_LENGTH = 16


class KeyPermissionError(RuntimeError):
    pass


class KeyEncryptionError(RuntimeError):
    """A key file is encrypted and can't be read, or isn't encrypted when it should be."""


def require_passphrase(app_env, passphrase):
    """Production must never run with keys stored in the clear."""
    if app_env != "production":
        return
    if not passphrase:
        raise KeyEncryptionError("KEY_PASSPHRASE must be set when APP_ENV=production")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise KeyEncryptionError(f"KEY_PASSPHRASE must be at least {MIN_PASSPHRASE_LENGTH} characters")


def fingerprint(public_key):
    """Short, stable id for a public key: first 16 hex chars of SHA-256 over its DER."""
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


class KeyService:
    SIGNING_PURPOSES = ("results",)

    def __init__(self, key_dir, passphrase=None):
        self.key_dir = key_dir
        self._passphrase = passphrase.encode() if passphrase else None
        self._secrets = {}  # decrypted secrets, so scrypt runs once per key, not per request
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
        self._ensure_secret("ballot_integrity.key")

    def _ensure_secret(self, name):
        if not os.path.exists(self._path(name)):
            self._write_secret(name, self._wrap_secret(name, os.urandom(32)))

    def _wrap_secret(self, name, secret):
        """Encrypt a 256-bit secret for storage. Unchanged if no passphrase is set."""
        if not self._passphrase:
            return secret
        salt, nonce = os.urandom(16), os.urandom(12)
        aead = AESGCM(self._kek(salt))
        return SECRET_MAGIC + salt + nonce + aead.encrypt(nonce, secret, name.encode())

    def _kek(self, salt):
        """Key-encryption key derived from the passphrase."""
        return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(self._passphrase)

    def _read_secret(self, name):
        if name in self._secrets:
            return self._secrets[name]
        with open(self._path(name), "rb") as f:
            data = f.read()
        encrypted = data.startswith(SECRET_MAGIC)
        if encrypted and not self._passphrase:
            raise KeyEncryptionError(f"{name} is encrypted, set KEY_PASSPHRASE to use it")
        if not encrypted and self._passphrase:
            raise KeyEncryptionError(f"{name} is not encrypted, run `flask --app app keys encrypt`")
        if encrypted:
            body = data[len(SECRET_MAGIC):]
            salt, nonce, ciphertext = body[:16], body[16:28], body[28:]
            try:
                data = AESGCM(self._kek(salt)).decrypt(nonce, ciphertext, name.encode())
            except InvalidTag:
                raise KeyEncryptionError(f"{name}: wrong passphrase, or the file was changed or swapped") from None
        self._secrets[name] = data
        return data

    def mfa_key(self):
        return self._read_secret("mfa.key")

    def audit_key(self):
        return self._read_secret("audit.key")

    def ballot_public_key(self):
        with open(self._path("ballot_public.pem"), "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def ballot_private_key(self):
        """Tally only. Nothing on the voting path should call this."""
        with open(self._path("ballot_private.pem"), "rb") as f:
            return self._load_private(f.read())

    def integrity_key(self):
        return self._read_secret("ballot_integrity.key")

    # ---- SR-20 ----

    def _private_pem(self, key):
        enc = (serialization.BestAvailableEncryption(self._passphrase)
               if self._passphrase else serialization.NoEncryption())
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)

    def _load_private(self, data):
        return serialization.load_pem_private_key(data, password=self._passphrase)

    def encrypt_at_rest(self):
        """Encrypt any key files that were created before KEY_PASSPHRASE was set.

        Keys already encrypted are left alone, so this is safe to run twice.
        Returns the files that were changed.
        """
        if not self._passphrase:
            raise KeyEncryptionError("set KEY_PASSPHRASE first")
        changed = []
        private_pems = ["ballot_private.pem"] + [
            os.path.join("signing", p, f"v{self._versions(p)[-1]}.pem") for p in self.SIGNING_PURPOSES]
        for name in private_pems:
            with open(self._path(name), "rb") as f:
                data = f.read()
            try:
                key = serialization.load_pem_private_key(data, password=None)
            except TypeError:
                continue  # already encrypted
            self._replace_secret(name, self._private_pem(key))
            changed.append(name)
        for name in ("audit.key", "mfa.key", "ballot_integrity.key"):
            with open(self._path(name), "rb") as f:
                data = f.read()
            if not data.startswith(SECRET_MAGIC):
                self._replace_secret(name, self._wrap_secret(name, data))
                changed.append(name)
        self._secrets.clear()
        return changed

    def _replace_secret(self, name, data):
        """Write to a temp file first, so a crash half way can't leave a broken key."""
        tmp = self._path(name) + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, self._path(name))

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

    # versioned signing keys: KEY_DIR/signing/<purpose>/pub-v<N>.pem for every
    # version, and v<N>.pem (private) for the current version only

    def _signing_dir(self, purpose):
        if purpose not in self.SIGNING_PURPOSES:
            raise ValueError(f"unknown signing purpose {purpose}")
        d = os.path.join(self.key_dir, "signing", purpose)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(os.path.join(self.key_dir, "signing"), 0o700)
        return d

    def _versions(self, purpose):
        """A version exists once its public key is in place."""
        d = self._signing_dir(purpose)
        return sorted(int(n[5:-4]) for n in os.listdir(d) if n.startswith("pub-v") and n.endswith(".pem"))

    @staticmethod
    def _write_atomic(path, data, mode):
        """Write to a temp file and rename it into place, so a crash never leaves a half-written key."""
        tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    def rotate(self, purpose):
        """Create a new signing key version and make it current. Returns its kid.

        Order matters: the private key is written first, then the public key,
        which is what makes the version count. A crash part way leaves the
        previous version current and every published public key readable.
        Once the new version is in place, older private keys are deleted, so
        only the current one could ever sign. Old public keys stay, so
        anything signed earlier still verifies.
        """
        d = self._signing_dir(purpose)
        version = (self._versions(purpose) or [0])[-1] + 1
        key = ed25519.Ed25519PrivateKey.generate()
        self._write_atomic(os.path.join(d, f"v{version}.pem"), self._private_pem(key), 0o600)
        self._write_atomic(os.path.join(d, f"pub-v{version}.pem"), key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
        for name in os.listdir(d):
            if name.startswith("v") and name.endswith(".pem") and name != f"v{version}.pem":
                os.remove(os.path.join(d, name))
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
