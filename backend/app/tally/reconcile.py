"""SR-19: reconciliation.

Three independent records have to agree:
  identity DB : voters marked "ballot issued"
  ballot DB   : ballot tokens issued / used
  ballot DB   : encrypted ballots stored
Rules:
  1. tokens issued       == voters marked as issued   (no forged or lost tokens)
  2. ballots stored      == tokens used               (no ballots without a token)
  3. per division: ballots <= voters issued there     (no stuffing into one seat)
A token issued but never used (voter closed the browser) is allowed and
reported, not an error.

Runs before every tally, on demand from the API, and from the command line
(`flask --app app reconcile`, exit code 1 on mismatch) so it can be
scheduled daily during pre-poll. Any mismatch raises an alert.
"""
import sys

import click
from flask import current_app
from sqlalchemy import func

from .. import audit
from ..extensions import db
from ..models import BallotToken, CastBallot, IntegrityAlert, Voter


def reconcile(record_alerts=True):
    issued = Voter.query.filter_by(ballot_issued=True).count()
    tokens = BallotToken.query.count()
    used = BallotToken.query.filter_by(used=True).count()
    ballots = CastBallot.query.count()
    problems = []

    if tokens != issued:
        problems.append(f"{tokens} ballot tokens exist but {issued} voters are marked as issued")
    if ballots != used:
        problems.append(f"{ballots} ballots stored but only {used} tokens were used")

    issued_by_div = dict(db.session.query(Voter.division, func.count())
                         .filter(Voter.ballot_issued.is_(True)).group_by(Voter.division).all())
    ballots_by_div = dict(db.session.query(CastBallot.division, func.count()).group_by(CastBallot.division).all())
    for div, n in sorted(ballots_by_div.items()):
        if n > issued_by_div.get(div, 0):
            problems.append(f"{div}: {n} ballots but only {issued_by_div.get(div, 0)} voters issued")

    result = {
        "ok": not problems,
        "voters_issued": issued,
        "tokens_issued": tokens,
        "tokens_used": used,
        "tokens_unused": tokens - used,
        "ballots_stored": ballots,
        "problems": problems,
    }
    if problems and record_alerts:
        for p in problems:
            db.session.add(IntegrityAlert(seq=None, reason=f"reconciliation: {p}"))
        db.session.commit()
        audit.record("reconciliation_failed", None, problems=problems)
    return result


def register_cli(app):
    @app.cli.command("reconcile")
    def reconcile_command():
        """Check voters issued vs tokens vs ballots (SR-19). Exit 1 on mismatch."""
        result = reconcile()
        for k in ("voters_issued", "tokens_issued", "tokens_used", "tokens_unused", "ballots_stored"):
            click.echo(f"{k}: {result[k]}")
        for p in result["problems"]:
            click.echo(f"PROBLEM: {p}", err=True)
        click.echo("OK" if result["ok"] else "MISMATCH")
        if not result["ok"]:
            sys.exit(1)
