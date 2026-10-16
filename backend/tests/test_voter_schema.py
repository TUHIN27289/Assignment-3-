import pytest
import sqlite3
from app.db import get_db_connection, init_db
from app.models import Voter

@pytest.fixture
def db_conn():
    """Fixture providing an initialized in-memory database connection for schema testing."""
    conn = get_db_connection("sqlite:///:memory:")
    init_db(conn)
    yield conn
    conn.close()

def test_voter_table_creation(db_conn):
    """Test that the voters table and indexes exist in the database."""
    cursor = db_conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='voters';")
    table = cursor.fetchone()
    assert table is not None
    assert table[0] == "voters"

def test_create_voter_default_values(db_conn):
    """Test creating a voter record and verifying default column values."""
    voter_id = Voter.create(db_conn, "VOTER-1001")
    assert voter_id is not None

    voter = Voter.get_by_identifier(db_conn, "VOTER-1001")
    assert voter is not None
    assert voter["voter_identifier"] == "VOTER-1001"
    assert voter["is_eligible"] is True
    assert voter["has_voted"] is False
    assert voter["voted_at"] is None

def test_voter_unique_identifier_constraint(db_conn):
    """Test that inserting duplicate voter_identifier violates the unique constraint."""
    Voter.create(db_conn, "VOTER-UNIQUE")
    
    with pytest.raises(sqlite3.IntegrityError):
        Voter.create(db_conn, "VOTER-UNIQUE")

def test_voter_not_null_identifier_constraint(db_conn):
    """Test that null voter_identifier violates the NOT NULL constraint."""
    with pytest.raises(sqlite3.IntegrityError):
        Voter.create(db_conn, None)

def test_voter_custom_eligibility_and_voted_status(db_conn):
    """Test creating voter with custom eligibility and has_voted status."""
    voter_id = Voter.create(db_conn, "VOTER-2002", is_eligible=False, has_voted=True, voted_at="2026-10-04 12:00:00")
    assert voter_id is not None

    voter = Voter.get_by_identifier(db_conn, "VOTER-2002")
    assert voter["is_eligible"] is False
    assert voter["has_voted"] is True
    assert voter["voted_at"] == "2026-10-04 12:00:00"
