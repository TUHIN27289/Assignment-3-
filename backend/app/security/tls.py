"""SR-16: TLS 1.3 only.

Used by run.py for the dev server. In the Docker setup the same rule is
applied in the nginx reverse proxy (ssl_protocols TLSv1.3).
"""
import ssl


def tls13_server_context(cert_file, key_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_file, key_file)
    return ctx
