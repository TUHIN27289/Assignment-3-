"""SR-18: verify a downloaded results package offline.

Anyone (media, candidates, the Court of Disputed Returns) can check a
package without trusting our server or the network in between. It only
needs the package file and the AEC's published results public key, which
should come from a trusted channel and be compared against the fingerprint
recorded at the key ceremony.

    python scripts/verify_results.py results-federal-2026-1.json public-keys.json

The key file can be the JSON from /api/keys/public or a single PEM file.
Exit code 0 means valid, 1 means NOT valid.
"""
import base64
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def fingerprint(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def load_keys(text):
    """Returns {kid: public_key}. The kid is recomputed from the key itself,
    so a key file can't pass off a different key under a trusted kid."""
    if text.lstrip().startswith("-----BEGIN"):
        pems = [text]
    else:
        pems = list(json.loads(text).get("results_signing_keys", {}).values())
    keys = {}
    for pem in pems:
        key = serialization.load_pem_public_key(pem.encode())
        keys[fingerprint(key)] = key
    return keys


def verify(doc, keys):
    """Returns (valid, message)."""
    try:
        payload, kid, sig = doc["package"], doc["kid"], doc["signature"]
    except (KeyError, TypeError):
        return False, "not a results package (needs package, kid and signature)"
    if doc.get("algorithm", "Ed25519") != "Ed25519":
        return False, f"unsupported algorithm {doc.get('algorithm')}"
    key = keys.get(kid)
    if key is None:
        return False, f"signed with key {kid}, which is not in the trusted key file"
    try:
        key.verify(base64.urlsafe_b64decode(sig), canonical(payload))
    except (InvalidSignature, ValueError, TypeError):
        return False, "signature does NOT match: the package was changed or not signed by this key"
    if doc.get("sha256") not in (None, hashlib.sha256(canonical(payload)).hexdigest()):
        return False, "sha256 field doesn't match the package contents"
    return True, (f"VALID: package #{payload.get('sequence')} for {payload.get('election_id')}, "
                  f"generated {payload.get('generated_at')}, signed with key {kid}")


def main(argv):
    if len(argv) != 3:
        print("usage: verify_results.py PACKAGE.json KEYS.json|KEY.pem")
        return 2
    with open(argv[1], encoding="utf-8") as f:
        doc = json.load(f)
    with open(argv[2], encoding="utf-8") as f:
        keys = load_keys(f.read())
    valid, message = verify(doc, keys)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
