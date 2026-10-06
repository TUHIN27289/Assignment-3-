"""Dev server over HTTPS, TLS 1.3 only (SR-16).
First run: python scripts/make_dev_cert.py
"""
import os

from app import create_app
from app.security.tls import tls13_server_context

CERT_DIR = os.path.join(os.path.dirname(__file__), "instance", "certs")

if __name__ == "__main__":
    app = create_app()
    ctx = tls13_server_context(os.path.join(CERT_DIR, "cert.pem"), os.path.join(CERT_DIR, "key.pem"))
    app.run(host="127.0.0.1", port=5000, ssl_context=ctx)
