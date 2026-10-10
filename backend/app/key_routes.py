"""SR-20: public key fingerprints + admin CLI for key rotation.

Rotation is a command-line job run by the key custodian on the server, not
an HTTP endpoint, so it can't be triggered remotely:
    flask --app app keys rotate results
    flask --app app keys fingerprints
"""
import json

import click
from flask import Blueprint, current_app, jsonify

bp = Blueprint("keys", __name__, url_prefix="/api/keys")


def public(view):
    view._public = True  # marker for the SR-02 deny-by-default check
    return view


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

    @group.command("fingerprints")
    def fingerprints():
        click.echo(json.dumps(current_app.extensions["keys"].fingerprints(), indent=2))

    from flask.cli import with_appcontext
    for cmd in group.commands.values():
        cmd.callback = with_appcontext(cmd.callback)
    app.cli.add_command(group)
