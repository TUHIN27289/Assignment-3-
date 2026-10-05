import pytest
import sqlite3
from app.db import get_db_connection, init_db
from app.receipts import ReceiptService

@pytest.fixture
def db_conn():
    """Fixture providing an initialized in-memory database connection for receipt testing."""
    conn = get_db_connection("sqlite:///:memory:")
    init_db(conn)
    yield conn
    conn.close()

def test_receipt_creation_success(db_conn):
    """Test 1: Receipt creation generates valid tracking code, timestamp, and HMAC signature."""
    voter_id = "VOTER-RECEIPT-101"
    receipt = ReceiptService.create_receipt(db_conn, voter_id, secret_key="test-key")

    assert receipt is not None
    assert "tracking_code" in receipt
    assert "signature" in receipt
    assert receipt["voter_identifier"] == voter_id
    assert len(receipt["tracking_code"]) == 32  # 16 bytes hex

    # Verify saved in database
    db_receipt = ReceiptService.get_by_tracking_code(db_conn, receipt["tracking_code"])
    assert db_receipt is not None
    assert db_receipt["voter_identifier"] == voter_id
    assert db_receipt["signature"] == receipt["signature"]

def test_receipt_signature_verification_success():
    """Test 2: Valid receipt data passes HMAC-SHA256 signature verification."""
    tracking_code = ReceiptService.generate_tracking_code()
    voter_id = "VOTER-RECEIPT-102"
    voted_at = "2026-10-04 12:00:00"
    secret_key = "test-secret-key"

    signature = ReceiptService.compute_signature(tracking_code, voter_id, voted_at, secret_key)
    is_valid = ReceiptService.verify_signature(tracking_code, voter_id, voted_at, signature, secret_key)

    assert is_valid is True

def test_receipt_tampering_detection():
    """Test 3: Tampering with tracking code, voter ID, timestamp, or signature fails verification."""
    tracking_code = ReceiptService.generate_tracking_code()
    voter_id = "VOTER-RECEIPT-103"
    voted_at = "2026-10-04 12:00:00"
    secret_key = "test-secret-key"

    signature = ReceiptService.compute_signature(tracking_code, voter_id, voted_at, secret_key)

    # Tampered tracking code
    assert ReceiptService.verify_signature("tampered_code", voter_id, voted_at, signature, secret_key) is False

    # Tampered voter ID
    assert ReceiptService.verify_signature(tracking_code, "TAMPERED_VOTER", voted_at, signature, secret_key) is False

    # Tampered timestamp
    assert ReceiptService.verify_signature(tracking_code, voter_id, "2026-10-04 12:00:01", signature, secret_key) is False

    # Tampered signature
    assert ReceiptService.verify_signature(tracking_code, voter_id, voted_at, "invalid_signature_hash", secret_key) is False

    # Wrong secret key
    assert ReceiptService.verify_signature(tracking_code, voter_id, voted_at, signature, secret_key="wrong-secret-key") is False

def test_receipt_contains_zero_voting_choices(db_conn):
    """Test 4: Proves receipt and database schema reveal NO candidate or voting choices."""
    voter_id = "VOTER-ANONYMOUS-99"
    receipt = ReceiptService.create_receipt(db_conn, voter_id, secret_key="test-key")

    # Allowed keys: strictly metadata and cryptographic signatures
    allowed_keys = {"tracking_code", "voter_identifier", "voted_at", "signature"}
    assert set(receipt.keys()) == allowed_keys

    # Explicit assertion that choice/candidate keys DO NOT exist
    assert "candidate" not in receipt
    assert "choice" not in receipt
    assert "vote" not in receipt
    assert "ballot" not in receipt
    assert "preference" not in receipt

    # Check DB schema columns
    cursor = db_conn.cursor()
    cursor.execute("PRAGMA table_info(receipts);")
    columns = [row["name"] for row in cursor.fetchall()]
    forbidden_terms = {"candidate", "choice", "ballot", "preference", "vote_choice"}
    for col in columns:
        assert col.lower() not in forbidden_terms

def test_invalid_and_malformed_receipts(db_conn):
    """Test 5: Verifies handling of invalid/malformed inputs."""
    # Missing voter identifier raises ValueError
    with pytest.raises(ValueError):
        ReceiptService.create_receipt(db_conn, "")

    with pytest.raises(ValueError):
        ReceiptService.create_receipt(db_conn, None)

    # Empty verification inputs return False
    assert ReceiptService.verify_signature(None, "V1", "2026-10-04", "sig") is False
    assert ReceiptService.verify_signature("TC1", "", "2026-10-04", "sig") is False
    assert ReceiptService.verify_signature("TC1", "V1", None, "sig") is False
    assert ReceiptService.verify_signature("TC1", "V1", "2026-10-04", "") is False

    # Non-existent tracking code lookup returns None
    assert ReceiptService.get_by_tracking_code(db_conn, "NON_EXISTENT_TC") is None
