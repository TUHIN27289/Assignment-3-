from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db, limiter
from .keys import KeyService, require_passphrase
from .security.http import init_http_security
from .security.rbac import init_rbac


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    limiter.init_app(app)
    init_http_security(app)
    init_rbac(app)
    passphrase = app.config.get("KEY_PASSPHRASE")
    require_passphrase(app.config.get("APP_ENV"), passphrase)  # SR-20: no plaintext keys in production
    if not passphrase and not app.testing:
        app.logger.warning("KEY_PASSPHRASE not set: keys are stored unencrypted (development only)")
    keys = KeyService(app.config["KEY_DIR"], passphrase)
    keys.check_permissions()  # SR-20: refuse to start with exposed keys
    app.extensions["keys"] = keys

    from .audit_routes import bp as audit_bp
    from .auth import bp as auth_bp
    from .ballot import bp as ballot_bp
    from .candidates import bp as candidates_bp
    from .key_routes import bp as keys_bp, register_cli
    from .tally import bp as tally_bp
    app.register_blueprint(audit_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(ballot_bp)
    app.register_blueprint(candidates_bp)
    app.register_blueprint(tally_bp)
    app.register_blueprint(keys_bp)
    register_cli(app)
    from .tally.reconcile import register_cli as register_reconcile_cli
    register_reconcile_cli(app)

    @app.errorhandler(HTTPException)
    def json_error(e):
        # Short JSON errors, no stack traces or internals leaked to the client
        return jsonify(error=e.name, message=e.description), e.code

    with app.app_context():
        db.create_all()
    return app
