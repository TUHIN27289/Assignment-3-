"""SR-02: role-based access control with least privilege.

Each role gets only the permissions its job needs. Routes ask for a
permission, not a role, so the whole policy lives in this one table.

Deny by default: any API route that has neither a permission nor an
explicit @public marker is refused. Forgetting a decorator fails closed.
"""
from flask import abort, current_app, request

PERMISSIONS = {
    "voter": {"self:read", "ballot:vote"},
    "enrolment_officer": {"self:read", "enrolment:read", "enrolment:write"},
    "delegate": {"self:read", "candidates:read", "candidates:write"},
    "tally_officer": {"self:read", "tally:run", "tally:reconcile"},
    "auditor": {"self:read", "audit:read", "tally:reconcile"},
}


def has_permission(role, permission):
    return permission in PERMISSIONS.get(role, set())


def public(view):
    """Marks a route that deliberately needs no login (e.g. anonymous ballot casting)."""
    view._public = True
    return view


def _default_deny():
    if request.endpoint is None or request.method == "OPTIONS":
        return  # 404s and CORS preflight
    view = current_app.view_functions[request.endpoint]
    if not getattr(view, "_public", False) and not getattr(view, "_permission", None):
        current_app.logger.error("route %s has no access rule, denied", request.endpoint)
        abort(403)


def init_rbac(app):
    app.before_request(_default_deny)
