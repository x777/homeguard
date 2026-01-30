"""Tool definitions and risk levels."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolResult:
    success: bool
    data: Any
    error: Optional[str] = None


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "scan_network",
            "description": "Discover all devices connected to the local network.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_ports",
            "description": "Scan a device for open ports. Use 'quick' or 'full' mode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Target IP address"},
                    "mode": {"type": "string", "enum": ["quick", "full"]},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_service_info",
            "description": "Get information about a service on a port.",
            "parameters": {
                "type": "object",
                "properties": {"port": {"type": "integer"}},
                "required": ["port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "identify_device",
            "description": "Identify device type based on characteristics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "mac": {"type": "string"},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "os_guess": {"type": "string"},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate security report with findings and recommendations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {"type": "array", "items": {"type": "string"}},
                    "recommendations": {"type": "array", "items": {"type": "string"}},
                    "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                },
                "required": ["findings", "recommendations", "risk_level"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_fix",
            "description": "Suggest a fix for a security issue.",
            "parameters": {
                "type": "object",
                "properties": {
                    "issue": {"type": "string"},
                    "command": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["issue", "command", "explanation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": "Search CVE database for vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {"keyword": {"type": "string"}},
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_threat_intel",
            "description": "Check IP or DNS against threat intelligence feeds.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "check_type": {"type": "string", "enum": ["ip", "dns", "vendor", "iot"]},
                    "vendor": {"type": "string"},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deep_scan_router",
            "description": "Deep scan router for vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deep_scan_iot",
            "description": "Deep scan IoT device for vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deep_scan_storage",
            "description": "Deep scan NAS/storage device.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_unknown_device",
            "description": "Probe unknown device with extended port scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "known_ports": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_default_credentials",
            "description": "Check for default credentials on web interface.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}, "port": {"type": "integer"}},
                "required": ["ip", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_encryption",
            "description": "Check TLS/SSL encryption status.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_upnp_exposure",
            "description": "Check for UPnP exposure risks.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_firmware_age",
            "description": "Check firmware age from HTTP headers.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_dns_hijacking",
            "description": "Check for DNS hijacking indicators.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fingerprint_device",
            "description": "Create or match device fingerprint for identification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Device IP address"},
                    "action": {"type": "string", "enum": ["create", "match", "update"], "description": "Fingerprint action"},
                    "device_data": {"type": "object", "description": "Device scan data"},
                },
                "required": ["ip", "action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_known_devices",
            "description": "List all known device fingerprints.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "auto_fix_vulnerability",
            "description": "Generate automated fix for a specific vulnerability.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Device IP address"},
                    "vuln_id": {"type": "string", "description": "Vulnerability ID (telnet_exposed, weak_ssl, upnp_enabled, etc.)"},
                    "device_data": {"type": "object", "description": "Device scan data"},
                },
                "required": ["ip", "vuln_id", "device_data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_remediation",
            "description": "Execute a remediation plan (requires user approval).",
            "parameters": {
                "type": "object",
                "properties": {
                    "fix_plan": {"type": "object", "description": "Fix plan from auto_fix_vulnerability"},
                    "dry_run": {"type": "boolean", "description": "Preview mode (default: true)"},
                },
                "required": ["fix_plan"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_fixable_vulnerabilities",
            "description": "List all vulnerabilities that can be automatically fixed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_data": {"type": "object", "description": "Device scan data"},
                },
                "required": ["device_data"],
            },
        },
    },
]

TOOL_RISKS = {
    "scan_network": (RiskLevel.LOW, True),
    "scan_ports": (RiskLevel.LOW, True),
    "get_service_info": (RiskLevel.LOW, True),
    "identify_device": (RiskLevel.LOW, True),
    "generate_report": (RiskLevel.LOW, True),
    "suggest_fix": (RiskLevel.MEDIUM, False),
    "lookup_cve": (RiskLevel.LOW, True),
    "check_threat_intel": (RiskLevel.LOW, True),
    "deep_scan_router": (RiskLevel.LOW, True),
    "deep_scan_iot": (RiskLevel.LOW, True),
    "deep_scan_storage": (RiskLevel.LOW, True),
    "probe_unknown_device": (RiskLevel.LOW, True),
    "check_default_credentials": (RiskLevel.MEDIUM, True),
    "check_encryption": (RiskLevel.LOW, True),
    "check_upnp_exposure": (RiskLevel.LOW, True),
    "check_firmware_age": (RiskLevel.LOW, True),
    "check_dns_hijacking": (RiskLevel.LOW, True),
    "fingerprint_device": (RiskLevel.LOW, True),
    "list_known_devices": (RiskLevel.LOW, True),
    "auto_fix_vulnerability": (RiskLevel.HIGH, False),
    "execute_remediation": (RiskLevel.CRITICAL, False),
    "list_fixable_vulnerabilities": (RiskLevel.LOW, True),
}


def get_tool_risk(name: str) -> tuple[RiskLevel, bool]:
    """Get risk level and auto-approve status for a tool."""
    return TOOL_RISKS.get(name, (RiskLevel.MEDIUM, False))
