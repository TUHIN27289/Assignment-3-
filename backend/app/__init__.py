from flask import Flask
from app.config import Config

def create_app(config_class=Config):
    """Application factory for Flask backend foundation."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Automatically initialize database schema on application startup
    try:
        from app.db import init_db
        init_db(app.config.get("DATABASE_URL"))
    except Exception:
        pass

    # Register routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app
