"""Port scanning functionality."""

import socket
from typing import Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .services import QUICK_PORTS, FULL_PORTS, get_service_info


@dataclass
class PortResult:
    """Result of a port scan."""

    port: int
    is_open: bool
    service: str = "Unknown"
    protocol: str = "tcp"
    risk: str = "medium"
    banner: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Attempt to grab service banner."""
    try:
        if port in (80, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port != 22:
            sock.send(b"\r\n")

        sock.settimeout(0.5)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        return banner[:100] if banner else None
    except Exception:
        return None


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[PortResult]:
    """Scan a single port using TCP connect."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            service, protocol, risk = get_service_info(port)
            banner = grab_banner(sock, port)
            sock.close()
            return PortResult(
                port=port, is_open=True, service=service, protocol=protocol, risk=risk, banner=banner
            )
        sock.close()
    except (socket.timeout, socket.error):
        pass
    return None


def scan_ports(
    ip: str,
    ports: Optional[list[int]] = None,
    quick: bool = True,
    timeout: float = 2.0,  # Increased from 1.0 for better detection
    max_workers: int = 50,
) -> list[PortResult]:
    """
    Scan multiple ports on a target IP.

    Args:
        ip: Target IP address
        ports: List of ports to scan
        quick: Use quick scan if ports not specified
        timeout: Connection timeout per port
        max_workers: Concurrent scan threads
    """
    if ports is None:
        ports = QUICK_PORTS if quick else FULL_PORTS

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result and result.is_open:
                open_ports.append(result)

    open_ports.sort(key=lambda p: p.port)
    return open_ports
