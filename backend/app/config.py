import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-placeholder")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    
    # PostgreSQL Configuration
    POSTGRES_USER = os.getenv("POSTGRES_USER", "voting_user")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "voting_password")
    POSTGRES_DB = os.getenv("POSTGRES_DB", "voting_db")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
    
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-key"
