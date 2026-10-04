import pytest
import sqlite3
import psycopg2
import threading
import tempfile
import os
from app.db import get_db_connection, init_db
from app.models import Voter

@pytest.fixture
def db_conn():
    """Fixture providing an initialized in-memory database connection for unit testing."""
    conn = get_db_connection("sqlite:///:memory:")
    init_db(conn)
    yield conn
    conn.close()

def test_eligible_voter_can_vote_once(db_conn):
    """Test A: An eligible, unvoted voter can cast a vote once successfully."""
    voter_id = Voter.create(db_conn, "VOTER-ELIGIBLE-1", is_eligible=True, has_voted=False)
    assert voter_id is not None

    result = Voter.cast_vote_once(db_conn, "VOTER-ELIGIBLE-1")
    assert result["success"] is True
    assert result["status"] == "SUCCESS"
    assert result["voter"] is not None
    assert result["voter"]["has_voted"] is True
    assert result["voter"]["voted_at"] is not None

def test_same_voter_cannot_vote_twice(db_conn):
    """Test B: A voter cannot vote a second time."""
    Voter.create(db_conn, "VOTER-DOUBLE-1", is_eligible=True, has_voted=False)

    # First vote attempt succeeds
    first_result = Voter.cast_vote_once(db_conn, "VOTER-DOUBLE-1")
    assert first_result["success"] is True
    assert first_result["status"] == "SUCCESS"
    initial_voted_at = first_result["voter"]["voted_at"]

    # Second vote attempt fails
    second_result = Voter.cast_vote_once(db_conn, "VOTER-DOUBLE-1")
    assert second_result["success"] is False
    assert second_result["status"] == "ALREADY_VOTED"
    assert second_result["voter"]["has_voted"] is True
    assert second_result["voter"]["voted_at"] == initial_voted_at

def test_ineligible_voter_cannot_vote(db_conn):
    """Test C: An ineligible voter cannot cast a vote."""
    Voter.create(db_conn, "VOTER-INELIGIBLE-1", is_eligible=False, has_voted=False)

    result = Voter.cast_vote_once(db_conn, "VOTER-INELIGIBLE-1")
    assert result["success"] is False
    assert result["status"] == "INELIGIBLE"

    voter = Voter.get_by_identifier(db_conn, "VOTER-INELIGIBLE-1")
    assert voter["has_voted"] is False
    assert voter["voted_at"] is None

def test_unknown_voter_cannot_vote(db_conn):
    """Test D: An unknown voter identifier is rejected."""
    result = Voter.cast_vote_once(db_conn, "UNKNOWN-VOTER-ID")
    assert result["success"] is False
    assert result["status"] == "NOT_FOUND"

def test_sqlite_concurrent_voting_race_condition():
    """
    Test E (SQLite): Unit-test level concurrency check using file-backed SQLite.
    Note: PostgreSQL is the production database. SQLite is used here only for lightweight local testing.
    This test demonstrates concurrent conditional-update execution in SQLite test environment
    but does not replace PostgreSQL row-level lock verification.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        database_url = f"sqlite:///{db_path}"
        init_conn = get_db_connection(database_url)
        init_db(init_conn)
        Voter.create(init_conn, "CONCURRENT-VOTER-1", is_eligible=True, has_voted=False)
        init_conn.close()

        num_threads = 10
        results = []
        threads = []

        def worker():
            conn = get_db_connection(database_url)
            res = Voter.cast_vote_once(conn, "CONCURRENT-VOTER-1")
            results.append(res)
            conn.close()

        for _ in range(num_threads):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        successes = [r for r in results if r["success"] is True]
        failures = [r for r in results if r["success"] is False]

        assert len(successes) == 1
        assert len(failures) == num_threads - 1
        assert successes[0]["status"] == "SUCCESS"
        for f in failures:
            assert f["status"] == "ALREADY_VOTED"

        # Verify final database state
        check_conn = get_db_connection(database_url)
        final_voter = Voter.get_by_identifier(check_conn, "CONCURRENT-VOTER-1")
        assert final_voter["has_voted"] is True
        assert final_voter["voted_at"] is not None
        check_conn.close()

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_postgres_concurrent_voting_race_condition():
    """
    Test E (PostgreSQL): PostgreSQL-backed concurrency test verifying true row-level locking
    and atomic update behavior in the production database (PostgreSQL 15).
    Runs when PostgreSQL is reachable on localhost:5432 or via DATABASE_URL.
    """
    pg_url = os.getenv("TEST_POSTGRES_URL", "postgresql://voting_user:voting_password@localhost:5432/voting_db")
    try:
        init_conn = psycopg2.connect(pg_url)
    except Exception as e:
        pytest.skip(f"PostgreSQL container is not reachable: {e}")

    init_db(init_conn)
    voter_id_test = "VOTER-PG-CONCURRENT-99"

    # Clean up existing test row if any
    cur = init_conn.cursor()
    cur.execute("DELETE FROM voters WHERE voter_identifier = %s;", (voter_id_test,))
    init_conn.commit()

    Voter.create(init_conn, voter_id_test, is_eligible=True, has_voted=False)
    init_conn.close()

    num_threads = 10
    results = []
    threads = []

    def worker():
        try:
            conn = psycopg2.connect(pg_url)
            res = Voter.cast_vote_once(conn, voter_id_test)
            results.append(res)
            conn.close()
        except Exception as ex:
            results.append({"success": False, "status": "ERROR", "error": str(ex)})

    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    successes = [r for r in results if r.get("success") is True]
    failures = [r for r in results if r.get("success") is False]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {results}"
    assert len(failures) == num_threads - 1
    assert successes[0]["status"] == "SUCCESS"
    for f in failures:
        assert f["status"] == "ALREADY_VOTED"

    # Verify final PostgreSQL database state
    verify_conn = psycopg2.connect(pg_url)
    final_voter = Voter.get_by_identifier(verify_conn, voter_id_test)
    assert final_voter["has_voted"] is True
    assert final_voter["voted_at"] is not None
    verify_conn.close()
