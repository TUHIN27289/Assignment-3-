import os
import sqlite3
import psycopg2

CREATE_VOTERS_TABLE_PG = """
CREATE TABLE IF NOT EXISTS voters (
    id SERIAL PRIMARY KEY,
    voter_identifier VARCHAR(255) NOT NULL UNIQUE,
    is_eligible BOOLEAN NOT NULL DEFAULT TRUE,
    has_voted BOOLEAN NOT NULL DEFAULT FALSE,
    voted_at TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_voters_lookup ON voters (voter_identifier, is_eligible, has_voted);
"""

CREATE_VOTERS_TABLE_SQLITE = """
CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_identifier VARCHAR(255) NOT NULL UNIQUE,
    is_eligible BOOLEAN NOT NULL DEFAULT 1,
    has_voted BOOLEAN NOT NULL DEFAULT 0,
    voted_at TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_voters_lookup ON voters (voter_identifier, is_eligible, has_voted);
"""

def get_db_connection(database_url=None):
    """
    Returns a database connection based on DATABASE_URL.
    Supports PostgreSQL via psycopg2 and SQLite for lightweight testing.
    """
    if database_url is None:
        database_url = os.getenv("DATABASE_URL", "sqlite:///:memory:")

    if database_url.startswith("sqlite://"):
        db_path = database_url.replace("sqlite:///", "").replace("sqlite://", "")
        if not db_path:
            db_path = ":memory:"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    else:
        conn = psycopg2.connect(database_url)
        return conn

def init_db(target=None):
    """
    Initializes the database schema (creates tables and indexes).
    Accepts either an active database connection object or a database_url string.
    """
    should_close = False
    if target is None or isinstance(target, str):
        database_url = target if isinstance(target, str) else os.getenv("DATABASE_URL", "sqlite:///:memory:")
        conn = get_db_connection(database_url)
        should_close = True
        is_sqlite = database_url.startswith("sqlite://")
    else:
        conn = target
        is_sqlite = isinstance(conn, sqlite3.Connection)

    cursor = conn.cursor()
    if is_sqlite:
        cursor.executescript(CREATE_VOTERS_TABLE_SQLITE)
    else:
        cursor.execute(CREATE_VOTERS_TABLE_PG)
    
    conn.commit()
    if should_close:
        conn.close()
