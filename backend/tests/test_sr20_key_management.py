"""SR-20: key management."""
import os
import pathlib
import re

import pytest
from cryptography.hazmat.primitives import serialization

from app import create_app
from app.config import TestConfig
from app.keys import KeyPermissionError, KeyService, fingerprint

REPO = pathlib.Path(__file__).resolve().parents[2]
ON_WINDOWS = os.name == "nt"
SKIP_ON_WINDOWS = pytest.mark.skipif(ON_WINDOWS, reason="Windows has no Unix permission bits")
SKIP_DIRS = {".venv", "node_modules", "instance", ".git", "__pycache__", "dist", "backups", ".pytest_cache"}


def test_every_purpose_has_its_own_key(tmp_path):
    k = KeyService(str(tmp_path / "k"))
    kid, signing = k.signing_key("results")
    ids = {fingerprint(k.ballot_public_key()), kid}
    assert len(ids) == 2
    assert k.integrity_key() != k.ballot_public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)[:32]


def test_no_private_keys_in_source_tree():
    pattern = re.compile(rb"-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----")
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            if os.path.getsize(path) < 2_000_000:
                with open(path, "rb") as f:
                    assert not pattern.search(f.read()), f"private key material in {path}"


def test_private_keys_encrypted_when_passphrase_set(tmp_path):
    k = KeyService(str(tmp_path / "k"), passphrase="correct horse battery staple")
    ballot_pem = (tmp_path / "k" / "ballot_private.pem").read_bytes()
    signing_pem = (tmp_path / "k" / "signing" / "results" / "v1.pem").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in ballot_pem and b"ENCRYPTED PRIVATE KEY" in signing_pem
    assert k.ballot_private_key() is not None  # loads with the passphrase


def test_encrypted_key_useless_without_passphrase(tmp_path):
    KeyService(str(tmp_path / "k"), passphrase="correct horse battery staple")
    with pytest.raises(TypeError):
        KeyService(str(tmp_path / "k")).ballot_private_key()


def test_wrong_passphrase_fails(tmp_path):
    KeyService(str(tmp_path / "k"), passphrase="correct horse battery staple")
    with pytest.raises(ValueError):
        KeyService(str(tmp_path / "k"), passphrase="wrong").ballot_private_key()

@SKIP_ON_WINDOWS
def test_refuses_to_start_with_world_readable_key(tmp_path):
    k = KeyService(str(tmp_path / "k"))
    os.chmod(tmp_path / "k" / "ballot_private.pem", 0o644)
    with pytest.raises(KeyPermissionError, match="ballot_private.pem"):
        k.check_permissions()

    class Cfg(TestConfig):
        KEY_DIR = str(tmp_path / "k")
    with pytest.raises(KeyPermissionError):
        create_app(Cfg)

@SKIP_ON_WINDOWS
def test_refuses_open_key_folder(tmp_path):
    k = KeyService(str(tmp_path / "k"))
    os.chmod(tmp_path / "k", 0o755)
    with pytest.raises(KeyPermissionError, match="0700"):
        k.check_permissions()


def test_rotation_keeps_old_public_key(tmp_path):
    k = KeyService(str(tmp_path / "k"))
    old_kid, old_key = k.signing_key("results")
    sig = old_key.sign(b"results v1")
    new_kid = k.rotate("results")
    assert new_kid != old_kid and k.signing_key("results")[0] == new_kid
    pubs = k.public_keys("results")
    assert set(pubs) == {old_kid, new_kid}
    serialization.load_pem_public_key(pubs[old_kid].encode()).verify(sig, b"results v1")


def test_unknown_signing_purpose_rejected(tmp_path):
    with pytest.raises(ValueError):
        KeyService(str(tmp_path / "k")).rotate("anything")


def test_public_key_endpoint(app, client):
    r = client.get("/api/keys/public").get_json()
    assert set(r["fingerprints"]) == {"ballot_encryption", "results_signing"}
    assert all("PRIVATE" not in pem for pem in r["results_signing_keys"].values())


def test_rotate_cli(app):
    runner = app.test_cli_runner()
    before = set(app.extensions["keys"].public_keys("results"))
    out = runner.invoke(args=["keys", "rotate", "results"])
    assert out.exit_code == 0 and "new results key" in out.output
    assert len(set(app.extensions["keys"].public_keys("results")) - before) == 1
