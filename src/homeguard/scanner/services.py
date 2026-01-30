"""Service and port definitions with risk levels."""

# port: (service_name, protocol, risk_level)
COMMON_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "tcp", "high"),
    22: ("SSH", "tcp", "medium"),
    23: ("Telnet", "tcp", "critical"),
    25: ("SMTP", "tcp", "medium"),
    53: ("DNS", "udp", "low"),
    80: ("HTTP", "tcp", "medium"),
    110: ("POP3", "tcp", "high"),
    111: ("RPC", "tcp", "high"),
    135: ("MSRPC", "tcp", "high"),
    139: ("NetBIOS", "tcp", "high"),
    143: ("IMAP", "tcp", "high"),
    443: ("HTTPS", "tcp", "low"),
    445: ("SMB", "tcp", "critical"),
    993: ("IMAPS", "tcp", "low"),
    995: ("POP3S", "tcp", "low"),
    1433: ("MSSQL", "tcp", "high"),
    1521: ("Oracle", "tcp", "high"),
    3306: ("MySQL", "tcp", "high"),
    3389: ("RDP", "tcp", "high"),
    5432: ("PostgreSQL", "tcp", "high"),
    5900: ("VNC", "tcp", "high"),
    6379: ("Redis", "tcp", "high"),
    8080: ("HTTP-Alt", "tcp", "medium"),
    8443: ("HTTPS-Alt", "tcp", "low"),
    27017: ("MongoDB", "tcp", "high"),
}

QUICK_PORTS = [
    21, 22, 23, 80, 443, 445, 548,  # Basic services
    3389, 5000, 5001, 8080, 8443,    # Admin/NAS
    554, 1883, 8008, 9000, 62078     # IoT/Streaming/Apple
]
FULL_PORTS = list(COMMON_PORTS.keys())


def get_service_info(port: int) -> tuple[str, str, str]:
    """Get service name, protocol, and risk level for a port."""
    return COMMON_PORTS.get(port, ("Unknown", "tcp", "medium"))


def get_risk_color(risk: str) -> str:
    """Get Rich color for risk level."""
    return {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}.get(
        risk, "white"
    )
