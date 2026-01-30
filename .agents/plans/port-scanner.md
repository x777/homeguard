# Feature: Port Scanner Module

## Feature Description

A port scanning module that scans discovered devices for open ports, identifies running services, and detects potential security risks. Integrates with the existing device discovery to provide comprehensive network security assessment.

## User Story

As a home network user
I want to scan devices for open ports and services
So that I can identify potential security vulnerabilities

## Feature Metadata

**Feature Type**: New Capability
**Estimated Complexity**: Medium
**Primary Systems Affected**: CLI client, scanner module
**Dependencies**: None (uses stdlib socket)

---

## CONTEXT REFERENCES

### Relevant Codebase Files - READ BEFORE IMPLEMENTING

- `src/homeguard/scanner/discovery.py` - Existing scanner patterns, ThreadPoolExecutor usage
- `src/homeguard/scanner/models.py` - Data model patterns
- `src/homeguard/cli.py` - CLI command patterns

### New Files to Create

```
src/homeguard/scanner/
├── ports.py          # Port scanning logic
└── services.py       # Service/port mapping database
```

### Common Ports Reference

| Port | Service | Risk Level |
|------|---------|------------|
| 21 | FTP | High (unencrypted) |
| 22 | SSH | Medium |
| 23 | Telnet | Critical (unencrypted) |
| 25 | SMTP | Medium |
| 53 | DNS | Low |
| 80 | HTTP | Medium |
| 110 | POP3 | High (unencrypted) |
| 139 | NetBIOS | High |
| 143 | IMAP | High (unencrypted) |
| 443 | HTTPS | Low |
| 445 | SMB | Critical |
| 3306 | MySQL | High |
| 3389 | RDP | High |
| 5432 | PostgreSQL | High |
| 8080 | HTTP-Alt | Medium |

---

## IMPLEMENTATION PLAN

### Phase 1: Service Database
Create port-to-service mapping with risk levels.

### Phase 2: Port Scanner
TCP connect scan with concurrent execution.

### Phase 3: CLI Integration
Add `ports` command and integrate with `scan`.

### Phase 4: Update Models
Add port info to Device model.

---

## STEP-BY-STEP TASKS

### Task 1: CREATE `src/homeguard/scanner/services.py`

Port-to-service mapping with risk assessment.

```python
"""Service and port definitions with risk levels."""

# Risk levels: critical, high, medium, low
COMMON_PORTS: dict[int, tuple[str, str, str]] = {
    # port: (service_name, protocol, risk_level)
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

# Quick scan: most common home network ports
QUICK_PORTS = [21, 22, 23, 80, 443, 445, 3389, 8080]

# Full scan: all common ports
FULL_PORTS = list(COMMON_PORTS.keys())


def get_service_info(port: int) -> tuple[str, str, str]:
    """Get service name, protocol, and risk level for a port."""
    return COMMON_PORTS.get(port, ("Unknown", "tcp", "medium"))


def get_risk_color(risk: str) -> str:
    """Get Rich color for risk level."""
    return {
        "critical": "red",
        "high": "orange1", 
        "medium": "yellow",
        "low": "green",
    }.get(risk, "white")
```

---

### Task 2: CREATE `src/homeguard/scanner/ports.py`

TCP connect scanner with concurrent execution.

```python
"""Port scanning functionality."""

import socket
from typing import Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from .services import COMMON_PORTS, QUICK_PORTS, FULL_PORTS, get_service_info


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
        return {
            "port": self.port,
            "is_open": self.is_open,
            "service": self.service,
            "protocol": self.protocol,
            "risk": self.risk,
            "banner": self.banner,
        }


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[PortResult]:
    """
    Scan a single port using TCP connect.
    
    Returns PortResult if open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            service, protocol, risk = get_service_info(port)
            banner = grab_banner(sock, port)
            sock.close()
            return PortResult(
                port=port,
                is_open=True,
                service=service,
                protocol=protocol,
                risk=risk,
                banner=banner,
            )
        sock.close()
        return None
    except (socket.timeout, socket.error):
        return None


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Attempt to grab service banner."""
    try:
        # Send probe for HTTP
        if port in (80, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner automatically
        else:
            sock.send(b"\r\n")
        
        sock.settimeout(0.5)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        return banner[:100] if banner else None
    except Exception:
        return None


def scan_ports(
    ip: str,
    ports: Optional[list[int]] = None,
    quick: bool = True,
    timeout: float = 1.0,
    max_workers: int = 50,
) -> list[PortResult]:
    """
    Scan multiple ports on a target IP.
    
    Args:
        ip: Target IP address
        ports: List of ports to scan (default: QUICK_PORTS or FULL_PORTS)
        quick: Use quick scan (fewer ports) if ports not specified
        timeout: Connection timeout per port
        max_workers: Concurrent scan threads
        
    Returns:
        List of PortResult for open ports only
    """
    if ports is None:
        ports = QUICK_PORTS if quick else FULL_PORTS
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port 
            for port in ports
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result and result.is_open:
                open_ports.append(result)
    
    # Sort by port number
    open_ports.sort(key=lambda p: p.port)
    return open_ports
```

---

### Task 3: UPDATE `src/homeguard/scanner/models.py`

Add ports field to Device model.

```python
# Add to Device dataclass:
ports: list = field(default_factory=list)

# Update to_dict to handle ports
```

---

### Task 4: UPDATE `src/homeguard/scanner/__init__.py`

Export new port scanning functions.

---

### Task 5: UPDATE `src/homeguard/cli.py`

Add `ports` command for standalone port scanning.

```python
@app.command()
def ports(
    target: str = typer.Argument(..., help="Target IP address to scan"),
    quick: bool = typer.Option(True, "--quick/--full", help="Quick scan vs full scan"),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Timeout per port"),
):
    """🔓 Scan a target for open ports."""
    # Implementation with Rich table output
```

---

### Task 6: CREATE tests

- `tests/test_scanner/test_ports.py`
- `tests/test_scanner/test_services.py`

---

## VALIDATION COMMANDS

```bash
# Syntax check
python -c "from homeguard.scanner.ports import scan_ports"

# Run tests
pytest tests/test_scanner/test_ports.py -v
pytest tests/test_scanner/test_services.py -v

# CLI test
homeguard ports --help
homeguard ports 192.168.0.1 --quick

# Lint
ruff check src/homeguard/scanner/ports.py
ruff check src/homeguard/scanner/services.py
```

---

## ACCEPTANCE CRITERIA

- [ ] Port scanner discovers open ports on target
- [ ] Service identification works for common ports
- [ ] Risk levels assigned correctly
- [ ] Banner grabbing works for HTTP/SSH
- [ ] CLI `ports` command works
- [ ] Concurrent scanning for speed
- [ ] All tests pass

---

## NOTES

### Design Decisions

1. **TCP Connect Scan**: Simple, reliable, no root required
2. **Quick vs Full**: Quick scan (8 ports) for speed, full scan (25 ports) for thoroughness
3. **Risk Levels**: Help users prioritize security concerns
4. **Banner Grabbing**: Optional service version detection

### Security Considerations

- Only scan networks you own/have permission to scan
- Rate limiting built into concurrent execution
- No SYN scan (would require root)
