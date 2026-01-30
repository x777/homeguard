"""Agent tools package - modular tool implementations."""

from .definitions import (
    RiskLevel,
    ToolResult,
    TOOL_DEFINITIONS,
    TOOL_RISKS,
    get_tool_risk,
)

from .network import (
    get_mac_vendor,
    identify_device_type,
    identify_device_enhanced,
    extract_vendor_from_scan_data,
)

from .deep_scan import (
    deep_scan_router,
    deep_scan_iot,
    deep_scan_storage,
    probe_unknown_device,
    detect_device_model,
)

from .security import (
    check_encryption,
    check_upnp_exposure,
    check_firmware_age,
    check_dns_hijacking,
    check_default_credentials,
)

from .threat import (
    lookup_cve,
    check_threat_intel,
)

from .executor import (
    execute_tool,
    format_tool_result,
)

from .validators import (
    validate_ip,
    validate_port,
    validate_network_cidr,
    is_local_network,
)

from .rate_limiter import (
    check_scan_rate,
    check_http_rate,
)

from .remediation import (
    auto_fix_vulnerability,
    execute_remediation,
    list_fixable_vulnerabilities,
    verify_fix,
)

__all__ = [
    # Definitions
    "RiskLevel",
    "ToolResult",
    "TOOL_DEFINITIONS",
    "TOOL_RISKS",
    "get_tool_risk",
    # Network
    "get_mac_vendor",
    "identify_device_type",
    "extract_vendor_from_scan_data",
    # Deep scan
    "deep_scan_router",
    "deep_scan_iot",
    "deep_scan_storage",
    "probe_unknown_device",
    "detect_device_model",
    # Security
    "check_encryption",
    "check_upnp_exposure",
    "check_firmware_age",
    "check_dns_hijacking",
    "check_default_credentials",
    # Threat
    "lookup_cve",
    "check_threat_intel",
    # Executor
    "execute_tool",
    "format_tool_result",
    # Validators
    "validate_ip",
    "validate_port",
    "validate_network_cidr",
    "is_local_network",
    # Rate limiting
    "check_scan_rate",
    "check_http_rate",
    # Remediation
    "auto_fix_vulnerability",
    "execute_remediation", 
    "list_fixable_vulnerabilities",
    "verify_fix",
]
