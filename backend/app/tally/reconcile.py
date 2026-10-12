"""SR-19: reconciliation.

Three independent records have to agree:
  identity DB : voters marked "ballot issued"
  ballot DB   : ballot tokens issued / used
  ballot DB   : encrypted ballots stored
Rules, checked for the whole election and again for every division, so a
problem in one seat can't hide behind matching totals:
  1. tokens issued  == voters marked as issued   (no forged or lost tokens,
                                                  no token for the wrong seat)
  2. ballots stored == tokens used               (no ballots without a token,
                                                  no ballots moved between seats)
A token issued but never used (voter closed the browser) is allowed and
reported, not an error.

Each distinct problem raises one alert. Running the check again doesn't
repeat alerts that are already open, so real new problems stand out.

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

    issued_by_div = _count_by_division(Voter, Voter.ballot_issued.is_(True))
    tokens_by_div = _count_by_division(BallotToken)
    used_by_div = _count_by_division(BallotToken, BallotToken.used.is_(True))
    ballots_by_div = _count_by_division(CastBallot)
    for div in sorted(set(issued_by_div) | set(tokens_by_div) | set(ballots_by_div)):
        voters_n, tokens_n = issued_by_div.get(div, 0), tokens_by_div.get(div, 0)
        used_n, ballots_n = used_by_div.get(div, 0), ballots_by_div.get(div, 0)
        if tokens_n != voters_n:
            problems.append(f"{div}: {tokens_n} ballot tokens but {voters_n} voters issued there")
        if ballots_n != used_n:
            problems.append(f"{div}: {ballots_n} ballots stored but {used_n} tokens used there")

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
            reason = f"reconciliation: {p}"[:255]
            if IntegrityAlert.query.filter_by(reason=reason).first() is None:
                db.session.add(IntegrityAlert(seq=None, reason=reason))
        db.session.commit()
        audit.record("reconciliation_failed", None, problems=problems)
    return result


def _count_by_division(model, *conditions):
    q = db.session.query(model.division, func.count()).filter(*conditions).group_by(model.division)
    return dict(q.all())


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
