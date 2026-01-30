"""Tool executor - routes tool calls to implementations."""

import json
from .definitions import ToolResult
from .network import identify_device_type
from .deep_scan import deep_scan_router, deep_scan_iot, deep_scan_storage, probe_unknown_device
from .security import check_encryption, check_upnp_exposure, check_firmware_age, check_dns_hijacking, check_default_credentials
from .threat import lookup_cve, check_threat_intel


def execute_tool(name: str, arguments: dict, backend_url: str = None) -> ToolResult:
    """Execute a tool and return result."""
    try:
        if name == "scan_network":
            from homeguard.scanner.discovery import scan_network
            result = scan_network()
            return ToolResult(
                success=True,
                data={
                    "network": result.network,
                    "device_count": len(result.devices),
                    "devices": [d.to_dict() for d in result.devices],
                },
            )

        elif name == "scan_ports":
            from homeguard.scanner.ports import scan_ports
            ip = arguments.get("ip")
            mode = arguments.get("mode", "quick")
            results = scan_ports(ip, quick=(mode == "quick"))
            return ToolResult(
                success=True,
                data={"ip": ip, "open_ports": [p.to_dict() for p in results]},
            )

        elif name == "get_service_info":
            from homeguard.scanner.services import get_service_info
            port = arguments.get("port")
            service, protocol, risk = get_service_info(port)
            return ToolResult(
                success=True,
                data={"port": port, "service": service, "protocol": protocol, "risk": risk},
            )

        elif name == "identify_device":
            ip = arguments.get("ip", "")
            mac = arguments.get("mac", "Unknown")
            open_ports = arguments.get("open_ports", [])
            os_guess = arguments.get("os_guess", "Unknown")
            device_type = identify_device_type(ip, mac, open_ports, os_guess)
            return ToolResult(success=True, data=device_type)

        elif name == "generate_report":
            return ToolResult(success=True, data=arguments)

        elif name == "suggest_fix":
            return ToolResult(success=True, data=arguments)

        elif name == "lookup_cve":
            keyword = arguments.get("keyword")
            return lookup_cve(keyword, backend_url)

        elif name == "check_threat_intel":
            ip = arguments.get("ip")
            check_type = arguments.get("check_type", "ip")
            vendor = arguments.get("vendor")
            return check_threat_intel(ip, check_type, backend_url, vendor)

        elif name == "deep_scan_router":
            ip = arguments.get("ip")
            result = deep_scan_router(ip)
            return ToolResult(success=True, data=result)

        elif name == "deep_scan_iot":
            ip = arguments.get("ip")
            result = deep_scan_iot(ip)
            return ToolResult(success=True, data=result)

        elif name == "deep_scan_storage":
            ip = arguments.get("ip")
            result = deep_scan_storage(ip)
            return ToolResult(success=True, data=result)

        elif name == "probe_unknown_device":
            ip = arguments.get("ip")
            known_ports = arguments.get("known_ports", [])
            result = probe_unknown_device(ip, known_ports)
            return ToolResult(success=True, data=result)

        elif name == "check_default_credentials":
            ip = arguments.get("ip")
            port = arguments.get("port", 80)
            result = check_default_credentials(ip, port)
            return ToolResult(success=True, data=result)

        elif name == "check_encryption":
            ip = arguments.get("ip")
            result = check_encryption(ip)
            return ToolResult(success=True, data=result)

        elif name == "check_upnp_exposure":
            ip = arguments.get("ip")
            result = check_upnp_exposure(ip)
            return ToolResult(success=True, data=result)

        elif name == "check_firmware_age":
            ip = arguments.get("ip")
            result = check_firmware_age(ip)
            return ToolResult(success=True, data=result)

        elif name == "check_dns_hijacking":
            ip = arguments.get("ip")
            result = check_dns_hijacking(ip)
            return ToolResult(success=True, data=result)

        elif name == "fingerprint_device":
            from .fingerprint import DeviceFingerprinter
            
            ip = arguments.get("ip")
            action = arguments.get("action", "create")
            device_data = arguments.get("device_data", {})
            
            fingerprinter = DeviceFingerprinter()
            
            if action == "create":
                fp = fingerprinter.create_fingerprint(device_data)
                fp_id = fingerprinter.store_fingerprint(device_data)
                return ToolResult(success=True, data={"fingerprint": fp, "fingerprint_id": fp_id})
            
            elif action == "match":
                match = fingerprinter.match_device(device_data)
                return ToolResult(success=True, data={"match": match})
            
            elif action == "update":
                fp_id = device_data.get("fingerprint_id")
                if fp_id:
                    fingerprinter.update_fingerprint(fp_id, device_data)
                    return ToolResult(success=True, data={"updated": fp_id})
                else:
                    return ToolResult(success=False, error="No fingerprint_id provided")
            
            return ToolResult(success=False, error=f"Unknown action: {action}")

        elif name == "list_known_devices":
            from .fingerprint import DeviceFingerprinter
            
            fingerprinter = DeviceFingerprinter()
            devices = fingerprinter.list_known_devices()
            return ToolResult(success=True, data={"known_devices": devices, "count": len(devices)})

        elif name == "auto_fix_vulnerability":
            from .remediation import auto_fix_vulnerability
            
            ip = arguments.get("ip")
            vuln_id = arguments.get("vuln_id")
            device_data = arguments.get("device_data", {})
            
            return auto_fix_vulnerability(ip, vuln_id, device_data)

        elif name == "execute_remediation":
            from .remediation import execute_remediation
            
            fix_plan = arguments.get("fix_plan", {})
            dry_run = arguments.get("dry_run", True)
            
            return execute_remediation(fix_plan, dry_run)

        elif name == "list_fixable_vulnerabilities":
            from .remediation import list_fixable_vulnerabilities
            
            device_data = arguments.get("device_data", {})
            return list_fixable_vulnerabilities(device_data)

        else:
            return ToolResult(success=False, data=None, error=f"Unknown tool: {name}")

    except Exception as e:
        return ToolResult(success=False, data=None, error=str(e))


def format_tool_result(result: ToolResult) -> str:
    """Format tool result for LLM context."""
    if result.success:
        return json.dumps(result.data, indent=2)
    else:
        return f"Error: {result.error}"
