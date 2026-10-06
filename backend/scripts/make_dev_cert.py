"""Self-signed localhost certificate for development only."""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = os.path.join(os.path.dirname(__file__), "..", "instance", "certs")
os.makedirs(out, exist_ok=True)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                       x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256()))
with open(os.path.join(out, "cert.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
fd = os.open(os.path.join(out, "key.pem"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))
print("wrote", os.path.abspath(out))
