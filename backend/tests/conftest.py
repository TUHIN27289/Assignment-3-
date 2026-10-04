import pytest
import tempfile
import os
from app import create_app
from app.config import TestingConfig
from app.db import get_db_connection, init_db

@pytest.fixture
def app():
    """Application fixture initialized with a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    class CustomTestingConfig(TestingConfig):
        DATABASE_URL = f"sqlite:///{db_path}"

    app = create_app(CustomTestingConfig)

    conn = get_db_connection(app.config["DATABASE_URL"])
    init_db(conn)
    conn.close()

    yield app

    if os.path.exists(db_path):
        os.remove(db_path)

@pytest.fixture
def client(app):
    """Test client fixture for Flask backend API testing."""
    return app.test_client()
