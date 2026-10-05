import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-placeholder")
    RECEIPT_SECRET_KEY = os.getenv("RECEIPT_SECRET_KEY", SECRET_KEY)
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    
    # Diplomatic Mission IP Ranges Configuration (SR-12)
    # Comma-separated list of CIDR strings (e.g. "192.0.2.0/24,2001:db8::/32")
    DIPLOMATIC_MISSION_IP_RANGES = os.getenv("DIPLOMATIC_MISSION_IP_RANGES", "")

    # PostgreSQL Configuration
    POSTGRES_USER = os.getenv("POSTGRES_USER", "voting_user")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "voting_password")
    POSTGRES_DB = os.getenv("POSTGRES_DB", "voting_db")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
    
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )

class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-key"
    RECEIPT_SECRET_KEY = "test-receipt-secret-key"
    DATABASE_URL = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    DIPLOMATIC_MISSION_IP_RANGES = ""

