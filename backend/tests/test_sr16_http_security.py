"""SR-16: TLS 1.3 only, security headers, CORS allowlist, CSRF, cookie flags."""
import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.security.tls import tls13_server_context

from .conftest import csrf, login

FRONTEND = "https://localhost:5173"


def test_security_headers(client):
    r = client.get("/api/auth/csrf")
    h = r.headers
    assert "max-age=31536000" in h["Strict-Transport-Security"]
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Cache-Control"] == "no-store"


def test_cors_allows_frontend_only(client):
    ok = client.get("/api/auth/csrf", headers={"Origin": FRONTEND})
    assert ok.headers.get("Access-Control-Allow-Origin") == FRONTEND
    assert ok.headers.get("Access-Control-Allow-Credentials") == "true"
    bad = client.get("/api/auth/csrf", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in bad.headers


def test_post_without_csrf_token_is_blocked(client):
    csrf(client)
    r = client.post("/api/auth/login", json={"email": "voter1@test.local", "password": "pw-voter"})
    assert r.status_code == 403


def test_post_with_wrong_csrf_token_is_blocked(client):
    csrf(client)
    r = client.post("/api/auth/login", json={"email": "voter1@test.local", "password": "pw-voter"},
                    headers={"X-CSRF-Token": "not-the-token"})
    assert r.status_code == 403


def test_session_cookie_flags(client):
    login(client, "voter1@test.local", "pw-voter")
    cookie = client.get_cookie("session")
    assert cookie.secure and cookie.http_only and cookie.same_site == "Strict"


def test_login_rotates_session(client):
    before = csrf(client)
    after = login(client, "voter1@test.local", "pw-voter")
    assert before != after


def test_errors_do_not_leak_internals(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and "Traceback" not in r.get_data(as_text=True)


# ---- TLS: real handshakes against a local server ----

@pytest.fixture
def tls_server(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = tls13_server_context(str(cert_file), str(key_file))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


def _client(port, version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ctx.maximum_version = version
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        with ctx.wrap_socket(s) as tls:
            return tls.version()


def test_tls13_accepted(tls_server):
    assert _client(tls_server, ssl.TLSVersion.TLSv1_3) == "TLSv1.3"


def test_tls12_rejected(tls_server):
    with pytest.raises(ssl.SSLError):
        _client(tls_server, ssl.TLSVersion.TLSv1_2)
