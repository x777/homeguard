"""HomeGuard network scanner module."""

from .discovery import scan_network, get_local_ip, get_network_cidr, SCAPY_AVAILABLE
from .models import Device, ScanResult, PortResult
from .os_detect import guess_os_from_ttl, get_os_details
from .ports import scan_ports, scan_port
from .services import COMMON_PORTS, QUICK_PORTS, FULL_PORTS, get_service_info, get_risk_color

__all__ = [
    "scan_network",
    "get_local_ip",
    "get_network_cidr",
    "SCAPY_AVAILABLE",
    "Device",
    "ScanResult",
    "PortResult",
    "guess_os_from_ttl",
    "get_os_details",
    "scan_ports",
    "scan_port",
    "COMMON_PORTS",
    "QUICK_PORTS",
    "FULL_PORTS",
    "get_service_info",
    "get_risk_color",
]
