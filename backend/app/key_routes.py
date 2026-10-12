"""SR-20: public key fingerprints + admin CLI for key management.

These are command-line jobs run by the key custodian on the server, not
HTTP endpoints, so they can't be triggered remotely:
    flask --app app keys rotate results
    flask --app app keys fingerprints
    flask --app app keys encrypt      (after setting KEY_PASSPHRASE)
"""
import json

import click
from flask import Blueprint, current_app, jsonify

from . import audit
from .security.rbac import public

bp = Blueprint("keys", __name__, url_prefix="/api/keys")


@bp.get("/public")
@public
def public_keys():
    keys = current_app.extensions["keys"]
    return jsonify(fingerprints=keys.fingerprints(),
                   results_signing_keys=keys.public_keys("results"))


def register_cli(app):
    group = click.Group("keys", help="Key management (SR-20)")

    @group.command("rotate")
    @click.argument("purpose")
    def rotate(purpose):
        kid = current_app.extensions["keys"].rotate(purpose)
        click.echo(f"new {purpose} key: {kid}")

    @group.command("encrypt")
    def encrypt():
        """Encrypt key files created before KEY_PASSPHRASE was set."""
        changed = current_app.extensions["keys"].encrypt_at_rest()
        for name in changed:
            click.echo(f"encrypted {name}")
        click.echo(f"{len(changed)} key file(s) encrypted" if changed else "all keys already encrypted")
        if changed:
            audit.record("keys_encrypted_at_rest", None, files=changed)

    @group.command("fingerprints")
    def fingerprints():
        click.echo(json.dumps(current_app.extensions["keys"].fingerprints(), indent=2))

    from flask.cli import with_appcontext
    for cmd in group.commands.values():
        cmd.callback = with_appcontext(cmd.callback)
    app.cli.add_command(group)
