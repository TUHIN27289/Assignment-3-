"""SR-20: public key fingerprints + admin CLI for key management.

These are command-line jobs run by the key custodian on the server, not
HTTP endpoints, so they can't be triggered remotely:
    flask --app app keys rotate results
    flask --app app keys fingerprints
    flask --app app keys encrypt      (after setting KEY_PASSPHRASE)
"""
import getpass
import json

import click
from flask import Blueprint, current_app, jsonify

from . import audit
from .keys import KeyService
from .security.rbac import public

bp = Blueprint("keys", __name__, url_prefix="/api/keys")


@bp.get("/public")
@public
def public_keys():
    keys = current_app.extensions["keys"]
    return jsonify(fingerprints=keys.fingerprints(),
                   results_signing_keys=keys.public_keys("results"))


def _operator():
    """The OS account running the command, for the audit trail."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def register_cli(app):
    group = click.Group("keys", help="Key management (SR-20)")

    @group.command("rotate")
    @click.argument("purpose", type=click.Choice(KeyService.SIGNING_PURPOSES))
    def rotate(purpose):
        """Make a new signing key current. Old public keys are kept for verification."""
        keys = current_app.extensions["keys"]
        old_kid = keys.signing_key(purpose)[0]
        kid = keys.rotate(purpose)
        audit.record("key_rotated", None, purpose=purpose, old_kid=old_kid, new_kid=kid, operator=_operator())
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
