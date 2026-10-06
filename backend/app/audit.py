"""Audit hook (placeholder).

Every module calls record() for security-relevant events so the calls are
already in place. SR-04 owner replaces the body with the tamper-evident
hash-chained audit log. Never pass ballot contents or ballot tokens here.
"""
import logging

log = logging.getLogger("audit")


def record(event, actor=None, **details):
    log.info("audit event=%s actor=%s details=%s", event, actor, details)
