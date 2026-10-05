import ipaddress
from typing import List, Union, Optional


class DiplomaticIPValidator:
    """
    Server-side IP range validation service for overseas diplomatic mission access (SR-12).
    Determines whether a client IP belongs to configured diplomatic mission CIDR ranges.
    """

    @staticmethod
    def parse_cidr_ranges(
        ranges_config: Union[str, List[str], tuple, set, None]
    ) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """
        Parses raw configuration (comma/space/newline-separated string or sequence)
        into a list of ipaddress network objects.
        Safely ignores empty or malformed CIDR entries.
        """
        if not ranges_config:
            return []

        raw_entries: List[str] = []
        if isinstance(ranges_config, str):
            cleaned_str = ranges_config.replace("\n", ",").replace("\r", ",")
            raw_entries = [entry.strip() for entry in cleaned_str.split(",") if entry.strip()]
        elif isinstance(ranges_config, (list, tuple, set)):
            raw_entries = [str(entry).strip() for entry in ranges_config if entry and str(entry).strip()]
        else:
            return []

        parsed_networks = []
        for entry in raw_entries:
            try:
                # strict=False normalizes host bits (e.g. 192.0.2.5/24 -> 192.0.2.0/24)
                net = ipaddress.ip_network(entry, strict=False)
                parsed_networks.append(net)
            except (ValueError, TypeError):
                continue

        return parsed_networks

    @classmethod
    def is_ip_allowed(
        cls,
        client_ip: Optional[str],
        allowed_ranges_config: Union[str, List[str], tuple, set, None]
    ) -> bool:
        """
        Validates whether client_ip is a valid IPv4 or IPv6 address and falls within any
        of the allowed diplomatic mission CIDR ranges.

        Args:
            client_ip: The client IP address string (IPv4 or IPv6).
            allowed_ranges_config: Configured CIDR ranges (string or list of strings).

        Returns:
            bool: True if client_ip belongs to an allowed range; False otherwise.
        """
        if not client_ip or not isinstance(client_ip, str):
            return False

        client_ip = client_ip.strip()
        if not client_ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            # Malformed or invalid IP address
            return False

        networks = cls.parse_cidr_ranges(allowed_ranges_config)
        if not networks:
            return False

        for net in networks:
            if ip_obj in net:
                return True

        return False

    @staticmethod
    def extract_client_ip(request) -> Optional[str]:
        """
        Extracts the server-determined client IP address from a Flask request.
        Do NOT blindly trust client-supplied headers (e.g., X-Forwarded-For, X-Real-IP)
        to prevent IP spoofing attacks, unless behind a verified trusted proxy.
        Uses request.remote_addr as the authoritative client IP.
        """
        if request is None:
            return None
        return getattr(request, "remote_addr", None)
