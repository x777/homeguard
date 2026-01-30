"""Input validation for security tools."""

import ipaddress
import re


def validate_ip(ip: str) -> tuple[bool, str]:
    """Validate IP address is safe to scan."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return False, "Loopback addresses not allowed"
        if addr.is_multicast:
            return False, "Multicast addresses not allowed"
        if not addr.is_private:
            return False, "Only private network addresses allowed"
        return True, ""
    except ValueError:
        return False, "Invalid IP format"


def validate_port(port: int) -> tuple[bool, str]:
    """Validate port number."""
    if not isinstance(port, int):
        return False, "Port must be integer"
    if not (1 <= port <= 65535):
        return False, "Port out of range (1-65535)"
    return True, ""


def validate_network_cidr(network: str) -> tuple[bool, str]:
    """Validate network CIDR notation."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        if not net.is_private:
            return False, "Only private networks allowed"
        if net.prefixlen < 16:
            return False, "Network too large (min /16)"
        return True, ""
    except ValueError:
        return False, "Invalid CIDR format"


def is_local_network(ip: str, local_ip: str) -> bool:
    """Check if IP is in same /24 subnet as local IP."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        local_obj = ipaddress.ip_address(local_ip)
        
        if not ip_obj.is_private:
            return False
        
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return ip_obj in network
    except ValueError:
        return False
