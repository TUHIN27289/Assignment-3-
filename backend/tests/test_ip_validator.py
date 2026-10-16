import pytest
from flask import Flask
from app.config import Config, TestingConfig
from app.ip_validator import DiplomaticIPValidator


def test_ip_inside_allowed_ipv4_cidr():
    """Verify an IPv4 address inside an allowed CIDR range returns True."""
    allowed_ranges = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.1", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.100", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.254", allowed_ranges) is True


def test_ip_outside_allowed_ipv4_cidr():
    """Verify an IPv4 address outside an allowed CIDR range returns False."""
    allowed_ranges = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("198.51.100.1", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.3.1", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.1.255", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("10.0.0.1", allowed_ranges) is False


def test_boundary_ips():
    """Verify network, broadcast, and edge IP addresses."""
    allowed_ranges = "192.0.2.0/24"
    # Network and broadcast addresses are included in CIDR subnet range comparison
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.0", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.255", allowed_ranges) is True

    # Immediate boundaries outside the range
    assert DiplomaticIPValidator.is_ip_allowed("192.0.1.255", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.3.0", allowed_ranges) is False


def test_multiple_configured_cidr_ranges():
    """Verify parsing and validation across multiple CIDR ranges (IPv4 & IPv6)."""
    allowed_ranges = "192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.50", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("198.51.100.20", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::ffff", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("203.0.113.5", allowed_ranges) is False


def test_single_host_cidr():
    """Verify single-host /32 (IPv4) and /128 (IPv6) CIDR ranges."""
    ipv4_host = "192.0.2.42/32"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.42", ipv4_host) is True
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.43", ipv4_host) is False

    ipv6_host = "2001:db8::1234/128"
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::1234", ipv6_host) is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8::1235", ipv6_host) is False


def test_ipv6_cases():
    """Verify IPv6 validation inside, outside, and edge cases."""
    allowed_ranges = "2001:db8:1234::/48"
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8:1234::1", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8:1234:ffff:ffff:ffff:ffff:ffff", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("2001:db8:1235::1", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("fe80::1", allowed_ranges) is False


def test_malformed_ip_addresses():
    """Verify graceful handling of invalid or malformed IP address strings."""
    allowed_ranges = "192.0.2.0/24"
    assert DiplomaticIPValidator.is_ip_allowed("invalid_ip", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("256.300.1.1", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.300", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed("   ", allowed_ranges) is False
    assert DiplomaticIPValidator.is_ip_allowed(None, allowed_ranges) is False


def test_empty_and_missing_configuration():
    """Verify behavior when no diplomatic mission ranges are configured."""
    valid_ip = "192.0.2.1"
    assert DiplomaticIPValidator.is_ip_allowed(valid_ip, "") is False
    assert DiplomaticIPValidator.is_ip_allowed(valid_ip, None) is False
    assert DiplomaticIPValidator.is_ip_allowed(valid_ip, []) is False
    assert DiplomaticIPValidator.is_ip_allowed(valid_ip, "   ") is False


def test_malformed_cidr_configuration_recovery():
    """Verify that malformed entries in CIDR config are safely ignored while valid entries remain active."""
    allowed_ranges = "invalid_cidr_entry, 192.0.2.0/24, bad/prefix/format"
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.5", allowed_ranges) is True
    assert DiplomaticIPValidator.is_ip_allowed("10.0.0.1", allowed_ranges) is False


def test_app_config_integration(app):
    """Verify that configuration supplied via application config is used correctly."""
    app.config["DIPLOMATIC_MISSION_IP_RANGES"] = "192.0.2.0/24, 198.51.100.0/24"
    
    ranges_config = app.config.get("DIPLOMATIC_MISSION_IP_RANGES")
    
    assert DiplomaticIPValidator.is_ip_allowed("192.0.2.10", ranges_config) is True
    assert DiplomaticIPValidator.is_ip_allowed("198.51.100.50", ranges_config) is True
    assert DiplomaticIPValidator.is_ip_allowed("203.0.113.1", ranges_config) is False


def test_client_ip_extraction_security():
    """
    Verify client IP extraction uses server-determined remote_addr
    and does NOT trust spoofed client headers like X-Forwarded-For or X-Real-IP.
    """
    test_app = Flask(__name__)

    with test_app.test_request_context(
        "/",
        environ_base={"REMOTE_ADDR": "192.0.2.50"},
        headers={"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.2"}
    ):
        from flask import request
        extracted_ip = DiplomaticIPValidator.extract_client_ip(request)
        # Should be remote_addr (192.0.2.50), ignoring spoofed header values
        assert extracted_ip == "192.0.2.50"
        assert extracted_ip != "10.0.0.1"
        assert extracted_ip != "10.0.0.2"
