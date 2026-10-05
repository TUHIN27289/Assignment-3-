import os
import secrets
import hmac
import hashlib
import sqlite3
from datetime import datetime, timezone

def get_receipt_secret_key():
    """Retrieves the signing secret key from environment or default config."""
    return os.getenv("RECEIPT_SECRET_KEY", os.getenv("SECRET_KEY", "dev-secret-key-placeholder"))

class ReceiptService:
    """
    Cryptographic receipt and tracking code service for SR-10.
    Provides verifiable, signed voter receipts that reveal NO candidate or voting choices.
    """

    @staticmethod
    def generate_tracking_code():
        """Generates a 32-character cryptographically secure random tracking code."""
        return secrets.token_hex(16)

    @staticmethod
    def compute_signature(tracking_code, voter_identifier, voted_at, secret_key=None):
        """
        Computes HMAC-SHA256 signature for canonical receipt data.
        Canonical message: '{tracking_code}:{voter_identifier}:{voted_at}'
        """
        if not secret_key:
            secret_key = get_receipt_secret_key()

        key_bytes = secret_key.encode("utf-8")
        canonical_msg = f"{tracking_code}:{voter_identifier}:{voted_at}".encode("utf-8")
        return hmac.new(key_bytes, canonical_msg, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(tracking_code, voter_identifier, voted_at, signature, secret_key=None):
        """
        Verifies the digital signature of a receipt using constant-time comparison.
        Prevents timing side-channel attacks.
        """
        if not tracking_code or not voter_identifier or not voted_at or not signature:
            return False

        expected_sig = ReceiptService.compute_signature(tracking_code, voter_identifier, voted_at, secret_key)
        return hmac.compare_digest(expected_sig, signature)

    @staticmethod
    def create_receipt(conn, voter_identifier, voted_at=None, secret_key=None):
        """
        Creates, signs, and records a voter receipt in the database.
        Reveals NO voting choices or ballot content.
        """
        if not voter_identifier:
            raise ValueError("voter_identifier is required to issue a receipt")

        if voted_at is None:
            voted_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(voted_at, datetime):
            voted_at = voted_at.strftime("%Y-%m-%d %H:%M:%S")

        tracking_code = ReceiptService.generate_tracking_code()
        signature = ReceiptService.compute_signature(tracking_code, voter_identifier, voted_at, secret_key)

        cursor = conn.cursor()
        if isinstance(conn, sqlite3.Connection):
            query = """
                INSERT INTO receipts (tracking_code, voter_identifier, voted_at, signature)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (tracking_code, voter_identifier, voted_at, signature))
        else:
            query = """
                INSERT INTO receipts (tracking_code, voter_identifier, voted_at, signature)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (tracking_code, voter_identifier, voted_at, signature))

        conn.commit()

        # Returns receipt containing NO ballot choice data
        return {
            "tracking_code": tracking_code,
            "voter_identifier": voter_identifier,
            "voted_at": str(voted_at),
            "signature": signature
        }

    @staticmethod
    def get_by_tracking_code(conn, tracking_code):
        """Retrieves a receipt from the database by tracking code."""
        if not tracking_code:
            return None

        cursor = conn.cursor()
        if isinstance(conn, sqlite3.Connection):
            query = "SELECT tracking_code, voter_identifier, voted_at, signature, created_at FROM receipts WHERE tracking_code = ?"
            cursor.execute(query, (tracking_code,))
            row = cursor.fetchone()
            if row:
                return {
                    "tracking_code": row["tracking_code"],
                    "voter_identifier": row["voter_identifier"],
                    "voted_at": row["voted_at"],
                    "signature": row["signature"],
                    "created_at": row["created_at"]
                }
        else:
            query = "SELECT tracking_code, voter_identifier, voted_at, signature, created_at FROM receipts WHERE tracking_code = %s"
            cursor.execute(query, (tracking_code,))
            row = cursor.fetchone()
            if row:
                return {
                    "tracking_code": row[0],
                    "voter_identifier": row[1],
                    "voted_at": row[2],
                    "signature": row[3],
                    "created_at": row[4]
                }
        return None
