"""SR-12: Diplomatic mission IP restriction for overseas access.

Overseas voting endpoints restrict access exclusively to verified diplomatic mission CIDRs.
Validates client IP using server-authoritative remote_addr and rejects spoofed headers.
"""
from flask import Flask, request

from app.ip_validator import DiplomaticIPValidator
from .conftest import csrf, login, candidate_ids


def test_ip_inside_allowed_ipv4_cidr():
    """Verify an IPv4 address inside an allowed CIDR range returns True."""
    allowed = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.1", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.100", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.254", allowed) is True


def test_ip_outside_allowed_ipv4_cidr():
    """Verify an IPv4 address outside an allowed CIDR range returns False."""
    allowed = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("198.51.100.1", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.3.1", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed("10.0.0.1", allowed) is False


def test_boundary_ips():
    """Verify boundary and edge IP addresses."""
    allowed = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.0", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.255", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.1.255", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.3.0", allowed) is False


def test_multiple_configured_cidr_ranges():
    """Verify parsing and validation across multiple IPv4 & IPv6 CIDRs."""
    allowed = "192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.50", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("198.51.100.20", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::ffff", allowed) is True
    assert DiplomaticIPValidator.is_ip_allowed("203.0.113.5", allowed) is False


def test_single_host_cidr():
    """Verify single-host /32 (IPv4) and /128 (IPv6) CIDR ranges."""
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.42", "192.0.2.42/32") is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.43", "192.0.2.42/32") is False
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::1", "2001:db8::1/128") is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::2", "2001:db8::1/128") is False


def test_malformed_ip_addresses():
    """Graceful handling of invalid or malformed IP address strings."""
    allowed = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("invalid_ip", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed("256.300.1.1", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed("", allowed) is False
    assert DiplomaticIPValidator.is_ip_allowed(None, allowed) is False


def test_empty_and_missing_configuration_denies_by_default():
    """Empty or unconfigured diplomatic ranges fail closed (deny all)."""
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.1", "") is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.1", None) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.1", []) is False


def test_spoofed_headers_are_ignored():
    """Authoritative client IP extraction ignores X-Forwarded-For and X-Real-IP."""
    test_app = Flask(__name__)
    with test_app.test_request_context(
        "/",
        environ_base={"REMOTE_ADDR": "192.0.2.50"},
        headers={"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.2"}
    ):
        extracted = DiplomaticIPValidator.extract_client_ip(request)
        assert extracted == "192.0.2.50"


def test_overseas_token_allowed_from_diplomatic_ip(app, client):
    """Token request with X-Overseas-Voting from an authorized diplomatic IP succeeds."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"
    c = login(client, "voter1@test.local", "pw-voter")

    res = client.post(
        "/api/ballot/token",
        headers={"X-CSRF-Token": c, "X-Overseas-Voting": "true"},
        environ_base={"REMOTE_ADDR": "192.0.2.10"}
    )
    assert res.status_code == 200
    assert "ballot_token" in res.get_json()


def test_overseas_token_blocked_from_non_diplomatic_ip(app, client):
    """Token request with X-Overseas-Voting from outside diplomatic IP range is 403 Forbidden."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"
    c = login(client, "voter1@test.local", "pw-voter")

    res = client.post(
        "/api/ballot/token",
        headers={"X-CSRF-Token": c, "X-Overseas-Voting": "true"},
        environ_base={"REMOTE_ADDR": "198.51.100.1"}
    )
    assert res.status_code == 403
    data = res.get_json()
    assert "restricted to authorized diplomatic mission" in (data.get("message") or data.get("error"))


def test_overseas_token_rejects_spoofed_forwarded_header(app, client):
    """Attacker sending spoofed X-Forwarded-For from non-diplomatic IP is blocked."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"
    c = login(client, "voter1@test.local", "pw-voter")

    res = client.post(
        "/api/ballot/token",
        headers={
            "X-CSRF-Token": c,
            "X-Overseas-Voting": "true",
            "X-Forwarded-For": "192.0.2.10",
            "X-Real-IP": "192.0.2.10",
        },
        environ_base={"REMOTE_ADDR": "198.51.100.1"}
    )
    assert res.status_code == 403


def test_dedicated_overseas_endpoint_enforces_diplomatic_ip(app, client):
    """Dedicated /api/ballot/overseas/token endpoint enforces diplomatic IP."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"
    c = login(client, "voter1@test.local", "pw-voter")

    # From non-diplomatic IP
    blocked = client.post(
        "/api/ballot/overseas/token",
        headers={"X-CSRF-Token": c},
        environ_base={"REMOTE_ADDR": "10.0.0.1"}
    )
    assert blocked.status_code == 403

    # From diplomatic IP
    allowed = client.post(
        "/api/ballot/overseas/token",
        headers={"X-CSRF-Token": c},
        environ_base={"REMOTE_ADDR": "192.0.2.55"}
    )
    assert allowed.status_code == 200
    assert "ballot_token" in allowed.get_json()


def test_overseas_cast_enforces_diplomatic_ip(app, client):
    """Ballot cast with overseas flag is rejected if cast from non-diplomatic IP."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24"
    c = login(client, "voter1@test.local", "pw-voter")
    token = client.post("/api/ballot/token", headers={"X-CSRF-Token": c}).get_json()["ballot_token"]

    anon = app.test_client()
    body = {"ballot_token": token, "ballot": {"house": candidate_ids(app)}}

    blocked = anon.post(
        "/api/ballot/cast",
        json=body,
        headers={"X-CSRF-Token": csrf(anon), "X-Overseas-Voting": "true"},
        environ_base={"REMOTE_ADDR": "198.51.100.5"}
    )
    assert blocked.status_code == 403

    # Token should still be valid, now cast from diplomatic IP
    allowed = anon.post(
        "/api/ballot/cast",
        json=body,
        headers={"X-CSRF-Token": csrf(anon), "X-Overseas-Voting": "true"},
        environ_base={"REMOTE_ADDR": "192.0.2.1"}
    )
    assert allowed.status_code == 200
    assert "tracking_code" in allowed.get_json()
