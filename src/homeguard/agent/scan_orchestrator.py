"""Centralized scan orchestration - eliminates duplicate code between loop.py and TUI."""

from typing import Dict, Any, Callable, Optional, Tuple, List
from .tools import execute_tool, identify_device_type, identify_device_enhanced, get_mac_vendor, extract_vendor_from_scan_data


class ScanOrchestrator:
    """Orchestrates device scanning with consistent logic across CLI and TUI."""
    
    def __init__(self, backend_url: str):
        self.backend_url = backend_url
    
    def handle_scan_network(self, result_data: Dict[str, Any], scan_data: Dict[str, Any]) -> None:
        """Process scan_network results."""
        scan_data["network"] = result_data.get("network", scan_data.get("network", "Unknown"))
        for dev in result_data.get("devices", []):
            ip = dev.get("ip")
            mac = dev.get("mac", "Unknown")
            vendor = get_mac_vendor(mac)
            scan_data["device_map"][ip] = {
                "ip": ip,
                "mac": mac,
                "os_guess": dev.get("os_guess", "Unknown"),
                "device_type": "Unknown",
                "vendor": vendor,
                "open_ports": [],
                "risks": [],
            }
    
    def handle_scan_ports(self, ip: str, result_data: Dict[str, Any], scan_data: Dict[str, Any]) -> Tuple[str, List[int]]:
        """Process scan_ports results and trigger auto-scans."""
        if ip not in scan_data["device_map"]:
            return "Unknown", []
        
        ports = result_data.get("open_ports", [])
        scan_data["device_map"][ip]["open_ports"] = ports
        port_numbers = [p.get("port") for p in ports if p.get("port")]
        
        # Get banners if available
        banners = result_data.get("banners", {})
        hostname = scan_data["device_map"][ip].get("hostname")
        
        # Use enhanced identification with LLM for AI scans
        use_llm = scan_data.get("scan_mode") == "full"
        device_info = identify_device_enhanced(
            ip,
            scan_data["device_map"][ip].get("mac", "Unknown"),
            port_numbers,
            scan_data["device_map"][ip].get("os_guess", "Unknown"),
            hostname=hostname,
            banners=banners if banners else None,
            use_llm=use_llm,
            backend_url=self.backend_url if use_llm else None
        )
        device_type = device_info.get("device_type", "Unknown")
        scan_data["device_map"][ip]["device_type"] = device_type
        scan_data["device_map"][ip]["vendor"] = device_info.get("vendor", "Unknown")
        scan_data["device_map"][ip]["confidence"] = device_info.get("confidence", "low")
        
        # Create/match device fingerprint
        self._handle_fingerprinting(ip, scan_data["device_map"][ip])
        
        # Check for fixable vulnerabilities
        self._check_remediation(ip, scan_data["device_map"][ip])
        
        return device_type, port_numbers
    
    def run_deep_scan(
        self,
        ip: str,
        device_type: str,
        port_numbers: list[int],
        device_data: Dict[str, Any],
        log_callback: Optional[Callable] = None
    ) -> Optional[Dict[str, Any]]:
        """Run appropriate deep scan based on device type."""
        tool_name = self._get_deep_scan_tool(device_type)
        if not tool_name:
            return None
        
        if log_callback:
            log_callback("deep_scan", tool_name, {"ip": ip})
        
        args = {"ip": ip}
        if tool_name == "probe_unknown_device":
            args["known_ports"] = port_numbers
        
        result = execute_tool(tool_name, args)
        if result and result.success:
            device_data["deep_scan"] = result.data
            
            # Extract vendor from deep scan
            http_info = result.data.get("http_info", {})
            banners = result.data.get("banners", {})
            vendor = extract_vendor_from_scan_data(result.data, http_info, banners)
            if vendor != "Unknown":
                device_data["vendor"] = vendor
            
            # Router-specific checks
            if "Router" in device_type:
                self._run_router_checks(ip, device_data, log_callback)
            
            return result.data
        
        return None
    
    def run_security_checks(
        self,
        ip: str,
        device_data: Dict[str, Any],
        log_callback: Optional[Callable] = None
    ) -> None:
        """Run security checks on devices with web interfaces."""
        from .tools.deep_scan import detect_device_model
        
        # Model detection
        if log_callback:
            log_callback("security", "detect_device_model", {"ip": ip})
        
        model_info = detect_device_model(ip)
        if model_info.get("model"):
            device_data["model"] = model_info["model"]
        if model_info.get("firmware"):
            device_data["firmware_version"] = model_info["firmware"]
        
        # Encryption and firmware checks
        for check, key in [("check_encryption", "encryption_check"), ("check_firmware_age", "firmware_check")]:
            if log_callback:
                log_callback("security", check, {"ip": ip})
            result = execute_tool(check, {"ip": ip})
            if result and result.success:
                device_data[key] = result.data
    
    def run_threat_intel(
        self,
        ip: str,
        device_type: str,
        device_data: Dict[str, Any],
        log_callback: Optional[Callable] = None
    ) -> None:
        """Query threat intelligence for device."""
        vendor = device_data.get("vendor", "Unknown")
        model = device_data.get("model")
        
        if vendor and vendor != "Unknown":
            search_vendor = self._normalize_vendor(vendor)
            search_term = f"{search_vendor} {model}" if model else search_vendor
            
            if log_callback:
                log_callback("threat_intel", "check_threat_intel", {"vendor": search_term})
            
            ti_result = execute_tool(
                "check_threat_intel",
                {"ip": ip, "check_type": "vendor", "vendor": search_term},
                backend_url=self.backend_url
            )
            if ti_result and ti_result.success:
                device_data["threat_intel"] = ti_result.data
        
        # IoT-specific exploits
        if device_type in ["IoT Device", "Smart TV / Streaming Device", "IP Camera"]:
            search_vendor = self._normalize_vendor(vendor) if vendor != "Unknown" else "generic"
            iot_search = f"{search_vendor} {model}" if model else search_vendor
            
            if log_callback:
                log_callback("threat_intel", "check_threat_intel", {"iot": iot_search})
            
            ti_result = execute_tool(
                "check_threat_intel",
                {"ip": ip, "check_type": "iot", "vendor": iot_search},
                backend_url=self.backend_url
            )
            if ti_result and ti_result.success:
                existing = device_data.get("threat_intel", {})
                existing["iot_exploits"] = ti_result.data.get("exploits", [])
                device_data["threat_intel"] = existing
    
    def _get_deep_scan_tool(self, device_type: str) -> Optional[str]:
        """Get appropriate deep scan tool for device type."""
        if "Router" in device_type or "Gateway" in device_type:
            return "deep_scan_router"
        elif device_type in ["IoT Device", "Smart TV / Streaming Device", "IP Camera"]:
            return "deep_scan_iot"
        elif device_type in ["NAS / Storage", "Server"]:
            return "deep_scan_storage"
        elif device_type == "Unknown Device":
            return "probe_unknown_device"
        return None
    
    def _run_router_checks(self, ip: str, device_data: Dict[str, Any], log_callback: Optional[Callable]) -> None:
        """Run router-specific security checks."""
        for check in ["check_upnp_exposure", "check_dns_hijacking"]:
            if log_callback:
                log_callback("router_check", check, {"ip": ip})
            result = execute_tool(check, {"ip": ip})
            if result and result.success:
                key = "upnp_check" if "upnp" in check else "dns_check"
                device_data[key] = result.data
    
    def _normalize_vendor(self, vendor: str) -> str:
        """Normalize vendor name for threat intel search."""
        from .constants import VENDOR_MAPPINGS
        
        if not vendor or vendor == "Unknown":
            return vendor
        
        vendor_lower = vendor.lower()
        for pattern, normalized in VENDOR_MAPPINGS.items():
            if pattern in vendor_lower:
                return normalized
        
        return vendor.split()[0].lower() if vendor else vendor
    
    def _handle_fingerprinting(self, ip: str, device_data: Dict[str, Any]) -> None:
        """Create and store device fingerprint."""
        from datetime import datetime
        
        # Add scan timestamp
        device_data["scan_time"] = datetime.now().isoformat()
        
        # Try to match existing fingerprint first
        match_result = execute_tool("fingerprint_device", {
            "ip": ip,
            "action": "match",
            "device_data": device_data
        })
        
        if match_result and match_result.success:
            match = match_result.data.get("match")
            if match:
                # Update existing fingerprint
                fp_id = match["stored_info"]["fingerprint"]["fingerprint_id"]
                execute_tool("fingerprint_device", {
                    "ip": ip,
                    "action": "update",
                    "device_data": {**device_data, "fingerprint_id": fp_id}
                })
                
                # Enhance device info with stored data
                stored_info = match["stored_info"]["device_info"]
                if stored_info.get("model") and not device_data.get("model"):
                    device_data["model"] = stored_info["model"]
                
                device_data["fingerprint_match"] = {
                    "type": match["match_type"],
                    "confidence": match["confidence"],
                    "seen_count": match["stored_info"]["seen_count"]
                }
            else:
                # Create new fingerprint
                create_result = execute_tool("fingerprint_device", {
                    "ip": ip,
                    "action": "create",
                    "device_data": device_data
                })
                if create_result and create_result.success:
                    device_data["fingerprint_id"] = create_result.data["fingerprint_id"]
    
    def _check_remediation(self, ip: str, device_data: Dict[str, Any], log_callback: Optional[Callable] = None) -> None:
        """Check for fixable vulnerabilities and suggest remediation."""
        if log_callback:
            log_callback("remediation", "list_fixable_vulnerabilities", {"ip": ip})
        
        result = execute_tool("list_fixable_vulnerabilities", {"device_data": device_data})
        if result and result.success:
            vulns = result.data.get("vulnerabilities", [])
            if vulns:
                device_data["fixable_vulnerabilities"] = vulns
                device_data["remediation_available"] = True
                
                # Log critical/high severity vulnerabilities
                for vuln in vulns:
                    if vuln.get("severity") in ["critical", "high"]:
                        if log_callback:
                            severity_icon = "🔴" if vuln["severity"] == "critical" else "🟠"
                            log_callback("finding", f"{ip}: {severity_icon} {vuln['description']} (FIXABLE)", vuln["severity"])
            else:
                device_data["remediation_available"] = False
