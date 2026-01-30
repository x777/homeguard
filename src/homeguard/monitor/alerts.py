"""Alert types and models."""

from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class AlertType(Enum):
    NEW_DEVICE = "new_device"
    DEVICE_REMOVED = "device_removed"
    NEW_VULNERABILITY = "new_vulnerability"
    CONFIG_CHANGE = "config_change"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"


@dataclass
class Alert:
    type: AlertType
    severity: str  # critical, high, medium, low
    title: str
    description: str
    device_ip: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self):
        return {
            "type": self.type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "device_ip": self.device_ip,
            "timestamp": self.timestamp.isoformat(),
        }
