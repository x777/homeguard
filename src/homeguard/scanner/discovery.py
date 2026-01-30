"""Network device discovery using ARP and ICMP."""

import platform
import socket
import subprocess
import ipaddress
from typing import Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import Device, ScanResult
from .os_detect import guess_os_from_ttl

# Try to import scapy, but don't fail if unavailable
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf

    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    pass


def _validate_ip_for_ping(ip: str) -> bool:
    """Validate IP is safe to ping."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private and not addr.is_loopback
    except ValueError:
        return False


def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_cidr(ip: str, prefix: int = 24) -> str:
    """Convert IP to network CIDR notation."""
    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    return str(network)


def get_hostname(ip: str) -> Optional[str]:
    """Attempt to resolve hostname for IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def ping_host(ip: str) -> Optional[int]:
    """Ping a host and return TTL if alive."""
    if not _validate_ip_for_ping(ip):
        return None
    
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            output = result.stdout.lower()
            if "ttl=" in output:
                idx = output.find("ttl=")
                ttl_str = output[idx + 4 : idx + 8].split()[0]
                return int("".join(c for c in ttl_str if c.isdigit()))
        return None
    except (subprocess.TimeoutExpired, Exception):
        return None


def scan_with_scapy(network: str, timeout: int = 3) -> list[Device]:
    """Scan network using scapy ARP requests. Requires root/admin."""
    if not SCAPY_AVAILABLE:
        return []

    devices = []
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=timeout, verbose=False)[0]

        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            ttl = ping_host(ip)
            os_guess = guess_os_from_ttl(ttl) if ttl else "Unknown"

            devices.append(
                Device(
                    ip=ip,
                    mac=mac,
                    hostname=get_hostname(ip),
                    os_guess=os_guess,
                    ttl=ttl,
                )
            )
    except (PermissionError, Exception):
        pass

    return devices


def scan_with_ping(network: str, max_workers: int = 50) -> list[Device]:
    """Scan network using ping sweep (fallback method)."""
    devices = []
    net = ipaddress.IPv4Network(network, strict=False)

    def check_host(ip: str) -> Optional[Device]:
        ttl = ping_host(ip)
        if ttl is not None:
            return Device(
                ip=ip,
                mac="Unknown",
                hostname=get_hostname(ip),
                os_guess=guess_os_from_ttl(ttl),
                ttl=ttl,
            )
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, str(ip)): str(ip) for ip in net.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    return devices


def scan_network(
    network: Optional[str] = None, use_scapy: bool = True, timeout: int = 3
) -> ScanResult:
    """
    Scan network for devices.

    Args:
        network: CIDR notation (e.g., "192.168.1.0/24"). Auto-detects if not provided.
        use_scapy: Try scapy first (requires root)
        timeout: Scan timeout in seconds
    """
    if not network:
        local_ip = get_local_ip()
        network = get_network_cidr(local_ip)

    devices = []

    if use_scapy and SCAPY_AVAILABLE:
        devices = scan_with_scapy(network, timeout)

    if not devices:
        devices = scan_with_ping(network)

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))

    return ScanResult(
        network=network,
        scan_time=datetime.now(),
        devices=devices,
        scanner_os=platform.system(),
    )
