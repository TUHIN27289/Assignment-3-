"""Dev server over HTTPS, TLS 1.3 only (SR-16).
First run: python scripts/make_dev_cert.py
"""
import os

# Local dev server: development mode, so it starts without KEY_PASSPHRASE.
# Production must not use this file (the app defaults to production).
os.environ.setdefault("APP_ENV", "development")

from app import create_app  # noqa: E402  (APP_ENV must be set before the config loads)
from app.security.tls import tls13_server_context  # noqa: E402

CERT_DIR = os.path.join(os.path.dirname(__file__), "instance", "certs")

if __name__ == "__main__":
    app = create_app()
    ctx = tls13_server_context(os.path.join(CERT_DIR, "cert.pem"), os.path.join(CERT_DIR, "key.pem"))
    app.run(host="127.0.0.1", port=5000, ssl_context=ctx)
