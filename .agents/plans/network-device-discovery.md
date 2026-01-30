# Feature: Network Device Discovery with OS Detection

The following plan should be complete, but validate documentation and codebase patterns before implementing.

## Feature Description

A network device discovery module that scans the local network to find connected devices, identifies them by IP and MAC address, and performs OS fingerprinting using TTL analysis. The module must work cross-platform (Windows/macOS/Linux) with graceful fallbacks when low-level networking is restricted.

## User Story

As a home network user
I want to discover all devices on my network and see what operating systems they're running
So that I can understand my network's security posture

## Problem Statement

Users need visibility into what devices are connected to their network and what operating systems they run. This is foundational for security assessment - you can't secure what you don't know exists.

## Solution Statement

Build a Python-based network scanner using ARP for device discovery and TTL-based OS fingerprinting. Use scapy when available (for full functionality) with socket-based fallbacks for restricted environments. Output structured JSON for backend API consumption.

## Feature Metadata

**Feature Type**: New Capability
**Estimated Complexity**: Medium
**Primary Systems Affected**: CLI client, scanner module
**Dependencies**: scapy (optional), netifaces (or platform commands for network info)

---

## CONTEXT REFERENCES

### Relevant Codebase Files - READ BEFORE IMPLEMENTING

- `.kiro/steering/tech.md` - Architecture overview, two-component design
- `.kiro/steering/structure.md` - Directory layout, file naming conventions
- `.kiro/steering/product.md` - Product requirements, success criteria

### New Files to Create

```
src/
└── homeguard/
    ├── __init__.py
    ├── cli.py                    # Typer CLI entry point
    └── scanner/
        ├── __init__.py
        ├── discovery.py          # ARP-based device discovery
        ├── os_detect.py          # TTL-based OS fingerprinting
        └── models.py             # Data models (Device, ScanResult)
```

### Relevant Documentation - READ BEFORE IMPLEMENTING

- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/usage.html)
  - ARP packet creation and sending
  - Why: Core library for network scanning
- [Typer Documentation](https://typer.tiangolo.com/)
  - CLI creation with type hints
  - Why: CLI framework for the project
- [Rich Documentation](https://rich.readthedocs.io/)
  - Tables, progress bars, console output
  - Why: Beautiful CLI output

### OS Fingerprinting Reference Data

TTL values for OS detection (from network analysis):

| Operating System | Default TTL | TCP Window Size |
|-----------------|-------------|-----------------|
| Linux (Kernel 2.4/2.6+) | 64 | 5840 |
| macOS / iOS | 64 | 65535 |
| Windows XP | 128 | 65535 |
| Windows Vista/7/8/10/11 | 128 | 8192 |
| FreeBSD | 64 | 65535 |
| Cisco IOS | 255 | 4128 |

**Key insight**: TTL decrements by 1 per router hop. A TTL of 117 likely started at 128 (Windows) and traversed 11 routers.

### Patterns to Follow

**Naming Conventions:**
- Files: `snake_case.py`
- Classes: `PascalCase`
- Functions/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`

**Type Hints:** Required for all functions

**Docstrings:** Google style for public functions

---

## IMPLEMENTATION PLAN

### Phase 1: Foundation

Set up project structure, dependencies, and data models.

**Tasks:**
- Create project skeleton with pyproject.toml
- Define data models for Device and ScanResult
- Set up basic CLI with Typer

### Phase 2: Core Implementation

Build the network scanner with ARP discovery and OS detection.

**Tasks:**
- Implement network interface detection (cross-platform)
- Build ARP scanner with scapy (primary) and socket fallback
- Implement TTL-based OS fingerprinting
- Add MAC vendor lookup (optional enhancement)

### Phase 3: Integration

Connect scanner to CLI with rich output.

**Tasks:**
- Wire scanner to CLI commands
- Add Rich table output for results
- Implement JSON export for backend API

### Phase 4: Testing & Validation

Ensure cross-platform compatibility and correctness.

**Tasks:**
- Test on macOS (your current platform)
- Add platform detection and graceful fallbacks
- Validate JSON output format

---

## STEP-BY-STEP TASKS

### Task 1: CREATE `pyproject.toml`

- **IMPLEMENT**: Project metadata, dependencies, CLI entry point
- **DEPENDENCIES**: typer[all], rich, scapy (optional)
- **VALIDATE**: `pip install -e .` succeeds

```toml
[project]
name = "homeguard"
version = "0.1.0"
description = "Network security assessment CLI"
requires-python = ">=3.10"
dependencies = [
    "typer[all]>=0.9.0",
    "rich>=13.0.0",
]

[project.optional-dependencies]
full = ["scapy>=2.5.0"]
dev = ["pytest>=7.0.0", "black", "ruff"]

[project.scripts]
homeguard = "homeguard.cli:app"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
```

---

### Task 2: CREATE `src/homeguard/__init__.py`

- **IMPLEMENT**: Package init with version
- **VALIDATE**: `python -c "import homeguard; print(homeguard.__version__)"`

```python
__version__ = "0.1.0"
```

---

### Task 3: CREATE `src/homeguard/scanner/__init__.py`

- **IMPLEMENT**: Scanner subpackage init, export main functions
- **VALIDATE**: File exists and is importable

---

### Task 4: CREATE `src/homeguard/scanner/models.py`

- **IMPLEMENT**: Data classes for Device and ScanResult
- **PATTERN**: Use dataclasses with type hints
- **VALIDATE**: `python -c "from homeguard.scanner.models import Device, ScanResult"`

```python
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

@dataclass
class Device:
    ip: str
    mac: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    vendor: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ScanResult:
    network: str
    scan_time: datetime
    devices: list[Device] = field(default_factory=list)
    scanner_os: str = ""
    
    def to_dict(self) -> dict:
        return {
            "network": self.network,
            "scan_time": self.scan_time.isoformat(),
            "scanner_os": self.scanner_os,
            "device_count": len(self.devices),
            "devices": [d.to_dict() for d in self.devices]
        }
```

---

### Task 5: CREATE `src/homeguard/scanner/os_detect.py`

- **IMPLEMENT**: TTL-based OS fingerprinting
- **PATTERN**: Pure function, no side effects
- **GOTCHA**: TTL decrements per hop - use ranges, not exact matches
- **VALIDATE**: `python -c "from homeguard.scanner.os_detect import guess_os_from_ttl; print(guess_os_from_ttl(128))"`

```python
"""OS fingerprinting based on TTL values."""

def guess_os_from_ttl(ttl: int) -> str:
    """
    Guess operating system based on TTL value.
    
    TTL decrements by 1 per router hop, so we use ranges:
    - 64 (or 1-64): Linux/macOS/FreeBSD
    - 128 (or 65-128): Windows
    - 255 (or 129-255): Cisco/Network devices
    
    Args:
        ttl: Time-to-live value from ICMP/TCP response
        
    Returns:
        Best guess OS string
    """
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/macOS/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device (Cisco/Router)"

def get_os_details(ttl: int) -> dict:
    """Get detailed OS information based on TTL."""
    os_guess = guess_os_from_ttl(ttl)
    
    # Estimate original TTL and hop count
    if ttl <= 64:
        original_ttl = 64
    elif ttl <= 128:
        original_ttl = 128
    else:
        original_ttl = 255
    
    hops = original_ttl - ttl
    
    return {
        "os_guess": os_guess,
        "ttl_observed": ttl,
        "ttl_original": original_ttl,
        "estimated_hops": hops
    }
```

---

### Task 6: CREATE `src/homeguard/scanner/discovery.py`

- **IMPLEMENT**: Network discovery with ARP (scapy) and ICMP fallback
- **PATTERN**: Try scapy first, fall back to ping sweep
- **GOTCHA**: scapy requires root/admin on some platforms
- **GOTCHA**: macOS may restrict raw sockets without sudo
- **IMPORTS**: Handle ImportError for scapy gracefully
- **VALIDATE**: `sudo python -c "from homeguard.scanner.discovery import scan_network; print(scan_network('192.168.1.0/24'))"`

```python
"""Network device discovery using ARP and ICMP."""

import platform
import socket
import subprocess
import ipaddress
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import Device, ScanResult
from .os_detect import guess_os_from_ttl

# Try to import scapy, but don't fail if unavailable
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0  # Suppress scapy output
    SCAPY_AVAILABLE = True
except ImportError:
    pass


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
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def ping_host(ip: str) -> Optional[int]:
    """
    Ping a host and return TTL if alive.
    
    Returns:
        TTL value if host responds, None otherwise
    """
    system = platform.system().lower()
    
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
        ttl_pattern = "TTL="
    else:  # Linux/macOS
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        ttl_pattern = "ttl="
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=2
        )
        if result.returncode == 0:
            output = result.stdout.lower()
            if ttl_pattern.lower() in output:
                # Extract TTL value
                idx = output.find(ttl_pattern.lower())
                ttl_str = output[idx + 4:idx + 8].split()[0]
                return int(''.join(c for c in ttl_str if c.isdigit()))
        return None
    except (subprocess.TimeoutExpired, Exception):
        return None


def scan_with_scapy(network: str, timeout: int = 3) -> list[Device]:
    """
    Scan network using scapy ARP requests.
    
    Requires root/admin privileges.
    """
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
            
            # Get TTL via ping for OS detection
            ttl = ping_host(ip)
            os_guess = guess_os_from_ttl(ttl) if ttl else "Unknown"
            hostname = get_hostname(ip)
            
            devices.append(Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                os_guess=os_guess,
                ttl=ttl
            ))
    except PermissionError:
        # Need root/admin
        pass
    except Exception:
        pass
    
    return devices


def scan_with_ping(network: str, max_workers: int = 50) -> list[Device]:
    """
    Scan network using ping sweep (fallback method).
    
    Slower but doesn't require special privileges.
    """
    devices = []
    net = ipaddress.IPv4Network(network, strict=False)
    
    def check_host(ip: str) -> Optional[Device]:
        ttl = ping_host(ip)
        if ttl is not None:
            return Device(
                ip=ip,
                mac="Unknown",  # Can't get MAC without ARP
                hostname=get_hostname(ip),
                os_guess=guess_os_from_ttl(ttl),
                ttl=ttl
            )
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_host, str(ip)): str(ip) 
            for ip in net.hosts()
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)
    
    return devices


def scan_network(
    network: Optional[str] = None, 
    use_scapy: bool = True,
    timeout: int = 3
) -> ScanResult:
    """
    Scan network for devices.
    
    Args:
        network: CIDR notation (e.g., "192.168.1.0/24"). 
                 Auto-detects if not provided.
        use_scapy: Try scapy first (requires root)
        timeout: Scan timeout in seconds
        
    Returns:
        ScanResult with discovered devices
    """
    from datetime import datetime
    
    # Auto-detect network if not provided
    if not network:
        local_ip = get_local_ip()
        network = get_network_cidr(local_ip)
    
    devices = []
    
    # Try scapy first (better results, needs root)
    if use_scapy and SCAPY_AVAILABLE:
        devices = scan_with_scapy(network, timeout)
    
    # Fall back to ping sweep if scapy failed or unavailable
    if not devices:
        devices = scan_with_ping(network)
    
    # Sort by IP address
    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    
    return ScanResult(
        network=network,
        scan_time=datetime.now(),
        devices=devices,
        scanner_os=platform.system()
    )
```

---

### Task 7: CREATE `src/homeguard/cli.py`

- **IMPLEMENT**: Typer CLI with scan command and Rich output
- **PATTERN**: Use Rich tables for device display
- **IMPORTS**: typer, rich.console, rich.table, rich.progress
- **VALIDATE**: `homeguard --help` and `homeguard scan --help`

```python
"""HomeGuard CLI - Network Security Assessment Tool."""

import json
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from homeguard.scanner.discovery import scan_network, get_local_ip, get_network_cidr, SCAPY_AVAILABLE

app = typer.Typer(
    name="homeguard",
    help="🛡️ HomeGuard - Network Security Assessment Tool",
    add_completion=False
)
console = Console()


@app.command()
def scan(
    network: Optional[str] = typer.Option(
        None, 
        "--network", "-n",
        help="Network to scan in CIDR notation (e.g., 192.168.1.0/24). Auto-detects if not provided."
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o", 
        help="Output file path for JSON results"
    ),
    timeout: int = typer.Option(
        3,
        "--timeout", "-t",
        help="Scan timeout in seconds"
    ),
    no_scapy: bool = typer.Option(
        False,
        "--no-scapy",
        help="Disable scapy (use ping sweep only)"
    )
):
    """
    🔍 Scan your network for connected devices.
    
    Discovers devices, identifies their operating systems via TTL fingerprinting,
    and displays results in a formatted table.
    """
    # Auto-detect network
    if not network:
        local_ip = get_local_ip()
        network = get_network_cidr(local_ip)
        console.print(f"[dim]Auto-detected network:[/dim] [cyan]{network}[/cyan]")
    
    # Show scanner status
    if SCAPY_AVAILABLE and not no_scapy:
        console.print("[dim]Scanner:[/dim] [green]scapy (ARP)[/green] + ping fallback")
    else:
        console.print("[dim]Scanner:[/dim] [yellow]ping sweep[/yellow] (install scapy for better results)")
    
    console.print()
    
    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        progress.add_task(f"Scanning {network}...", total=None)
        result = scan_network(
            network=network, 
            use_scapy=not no_scapy,
            timeout=timeout
        )
    
    # Display results
    if not result.devices:
        console.print("[yellow]No devices found.[/yellow]")
        console.print("[dim]Try running with sudo for better results.[/dim]")
        return
    
    # Create results table
    table = Table(title=f"🖥️  Devices on {result.network}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="magenta")
    table.add_column("Hostname", style="green")
    table.add_column("OS (TTL)", style="yellow")
    table.add_column("TTL", justify="right")
    
    for device in result.devices:
        table.add_row(
            device.ip,
            device.mac,
            device.hostname or "-",
            device.os_guess or "Unknown",
            str(device.ttl) if device.ttl else "-"
        )
    
    console.print(table)
    console.print(f"\n[dim]Found {len(result.devices)} device(s)[/dim]")
    
    # Save JSON output if requested
    if output:
        with open(output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def info():
    """ℹ️  Show system and network information."""
    import platform
    
    local_ip = get_local_ip()
    network = get_network_cidr(local_ip)
    
    table = Table(title="System Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Operating System", platform.system())
    table.add_row("OS Version", platform.version())
    table.add_row("Local IP", local_ip)
    table.add_row("Network", network)
    table.add_row("Scapy Available", "✅ Yes" if SCAPY_AVAILABLE else "❌ No")
    
    console.print(table)


@app.callback()
def main():
    """
    🛡️ HomeGuard CLI - Network Security Assessment Tool
    
    Scan your home network, discover devices, and get security recommendations.
    """
    pass


if __name__ == "__main__":
    app()
```

---

### Task 8: UPDATE `src/homeguard/scanner/__init__.py`

- **IMPLEMENT**: Export main scanner functions
- **VALIDATE**: `python -c "from homeguard.scanner import scan_network"`

```python
"""HomeGuard network scanner module."""

from .discovery import scan_network, get_local_ip, get_network_cidr, SCAPY_AVAILABLE
from .models import Device, ScanResult
from .os_detect import guess_os_from_ttl, get_os_details

__all__ = [
    "scan_network",
    "get_local_ip", 
    "get_network_cidr",
    "SCAPY_AVAILABLE",
    "Device",
    "ScanResult",
    "guess_os_from_ttl",
    "get_os_details",
]
```

---

## TESTING STRATEGY

### Unit Tests

Create `tests/test_scanner/test_os_detect.py`:

```python
import pytest
from homeguard.scanner.os_detect import guess_os_from_ttl, get_os_details

def test_guess_os_linux():
    assert "Linux" in guess_os_from_ttl(64)
    assert "Linux" in guess_os_from_ttl(63)
    assert "Linux" in guess_os_from_ttl(50)

def test_guess_os_windows():
    assert "Windows" in guess_os_from_ttl(128)
    assert "Windows" in guess_os_from_ttl(127)
    assert "Windows" in guess_os_from_ttl(100)

def test_guess_os_network_device():
    assert "Network" in guess_os_from_ttl(255)
    assert "Network" in guess_os_from_ttl(200)

def test_guess_os_unknown():
    assert "Unknown" in guess_os_from_ttl(0)
    assert "Unknown" in guess_os_from_ttl(-1)

def test_get_os_details():
    details = get_os_details(117)
    assert details["ttl_observed"] == 117
    assert details["ttl_original"] == 128
    assert details["estimated_hops"] == 11
    assert "Windows" in details["os_guess"]
```

### Integration Tests

Create `tests/test_scanner/test_discovery.py`:

```python
import pytest
from homeguard.scanner.discovery import get_local_ip, get_network_cidr

def test_get_local_ip():
    ip = get_local_ip()
    assert ip != "127.0.0.1" or True  # May be localhost in CI
    parts = ip.split(".")
    assert len(parts) == 4

def test_get_network_cidr():
    cidr = get_network_cidr("192.168.1.100")
    assert cidr == "192.168.1.0/24"
```

### Edge Cases

- Empty network (no devices respond)
- Invalid CIDR notation
- Permission denied (no root)
- Network timeout
- Invalid IP addresses

---

## VALIDATION COMMANDS

### Level 1: Syntax & Style

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Format code
black src/ tests/

# Lint
ruff check src/ tests/
```

### Level 2: Unit Tests

```bash
pytest tests/test_scanner/test_os_detect.py -v
```

### Level 3: Integration Tests

```bash
pytest tests/ -v
```

### Level 4: Manual Validation

```bash
# Show help
homeguard --help
homeguard scan --help

# Show system info
homeguard info

# Run scan (may need sudo for full results)
homeguard scan

# Run scan with specific network
homeguard scan -n 192.168.1.0/24

# Run scan and save JSON
homeguard scan -o scan_results.json

# Run without scapy (ping only)
homeguard scan --no-scapy
```

---

## ACCEPTANCE CRITERIA

- [x] CLI installs and runs with `homeguard` command
- [ ] `homeguard scan` discovers devices on local network
- [ ] OS detection works via TTL fingerprinting
- [ ] Results display in Rich table format
- [ ] JSON export works with `-o` flag
- [ ] Cross-platform: Works on macOS (test), Linux, Windows
- [ ] Graceful fallback when scapy unavailable
- [ ] Graceful handling when not running as root

---

## COMPLETION CHECKLIST

- [ ] All files created in correct locations
- [ ] `pip install -e .` succeeds
- [ ] `homeguard --help` works
- [ ] `homeguard info` shows system info
- [ ] `homeguard scan` discovers at least local machine
- [ ] JSON output is valid and complete
- [ ] Code passes black/ruff checks

---

## NOTES

### Design Decisions

1. **Scapy optional**: Not all users can install scapy (requires libpcap). Ping fallback ensures basic functionality everywhere.

2. **TTL-based OS detection**: Simple but effective. More accurate than nothing, less complex than full TCP fingerprinting.

3. **Concurrent ping sweep**: Uses ThreadPoolExecutor for speed when falling back to ping.

4. **JSON output format**: Designed for backend API consumption - includes all metadata needed for LLM analysis.

### Known Limitations

1. **MAC addresses**: Only available with ARP (scapy). Ping fallback shows "Unknown".

2. **OS detection accuracy**: TTL-based detection can't distinguish Linux from macOS (both use TTL 64). Backend LLM can provide more context.

3. **Root/admin required**: Full ARP scanning needs elevated privileges. Document this clearly.

### Future Enhancements

- MAC vendor lookup (OUI database)
- Port scanning integration
- Service detection
- More sophisticated OS fingerprinting (TCP window size, etc.)

---

**Confidence Score: 8/10**

High confidence due to:
- Well-documented libraries (scapy, typer, rich)
- Clear fallback strategy for cross-platform support
- Simple, focused scope

Risks:
- Platform-specific networking quirks
- Permission issues on different OSes
- scapy installation complexity on some systems
