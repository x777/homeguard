"""Data models for network scanning."""

from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from datetime import datetime


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


@dataclass
class Device:
    """Represents a discovered network device."""

    ip: str
    mac: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    vendor: Optional[str] = None
    ports: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ports"] = [p.to_dict() if hasattr(p, "to_dict") else p for p in self.ports]
        return data


@dataclass
class ScanResult:
    """Results from a network scan."""

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
            "devices": [d.to_dict() for d in self.devices],
        }
