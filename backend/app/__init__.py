from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db, limiter
from .keys import KeyService
from .security.http import init_http_security


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    limiter.init_app(app)
    init_http_security(app)
    app.extensions["keys"] = KeyService(app.config["KEY_DIR"])

    from .auth import bp as auth_bp
    from .ballot import bp as ballot_bp
    from .tally import bp as tally_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(ballot_bp)
    app.register_blueprint(tally_bp)

    @app.errorhandler(HTTPException)
    def json_error(e):
        # Short JSON errors, no stack traces or internals leaked to the client
        return jsonify(error=e.name, message=e.description), e.code

    with app.app_context():
        db.create_all()
    return app
