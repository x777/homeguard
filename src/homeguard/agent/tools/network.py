"""Network and device identification tools."""

import json
import socket
import re
import urllib.request
import urllib.error
from typing import Optional, Dict, List, Tuple


def get_mac_vendor(mac: str) -> str:
    """Get vendor from MAC address via OUI API lookup."""
    if not mac or mac == "Unknown":
        return "Unknown"
    
    try:
        mac_clean = mac.replace(":", "").replace("-", "")[:6]
        req = urllib.request.Request(
            f"https://api.maclookup.app/v2/macs/{mac_clean}",
            headers={"User-Agent": "HomeGuard/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            if data.get("found") and data.get("company"):
                return data["company"]
    except Exception:
        pass
    
    return "Unknown"


def identify_device_type(ip: str, mac: str, open_ports: list[int], os_guess: str) -> dict:
    """Identify device type based on characteristics."""
    vendor = get_mac_vendor(mac)
    device_type = "Unknown Device"
    confidence = "low"
    details = []
    
    # Check if it's the gateway/router
    if ip.endswith(".1") or ip.endswith(".254"):
        if any(p in open_ports for p in [80, 443, 53, 8080]):
            device_type = "Router/Gateway"
            confidence = "high"
            details.append("Gateway IP address with typical router ports")
    
    port_set = set(open_ports)
    
    # Smart TV / Streaming
    if port_set & {8008, 8443, 9000, 8009}:
        device_type = "Smart TV / Streaming Device"
        confidence = "medium"
        details.append("Has casting/streaming ports")
    
    # Printer
    if port_set & {9100, 631, 515}:
        device_type = "Printer"
        confidence = "high"
        details.append("Has printing service ports")
    
    # NAS / Storage
    if port_set & {5000, 5001, 445, 139, 548}:
        if len(port_set & {5000, 5001, 445, 139, 548}) >= 2:
            device_type = "NAS / Storage Device"
            confidence = "medium"
            details.append("Has file sharing ports")
    
    # Camera / DVR
    if port_set & {554, 8554, 37777}:
        device_type = "IP Camera / DVR"
        confidence = "medium"
        details.append("Has RTSP/streaming ports")
    
    # Game Console
    if port_set & {3074, 3478, 3479, 3480}:
        device_type = "Game Console"
        confidence = "medium"
        details.append("Has gaming network ports")
    
    # Computer based on OS
    if os_guess:
        if "Windows" in os_guess and device_type == "Unknown Device":
            device_type = "Windows Computer"
            confidence = "medium"
            if 3389 in port_set:
                details.append("RDP enabled")
            if 445 in port_set:
                details.append("File sharing enabled")
        elif "Linux" in os_guess or "macOS" in os_guess:
            if device_type == "Unknown Device":
                device_type = "Linux/Mac Computer"
                confidence = "medium"
            if 22 in port_set:
                details.append("SSH enabled")
    
    # Vendor-based identification
    if vendor != "Unknown":
        details.append(f"Manufacturer: {vendor}")
        if vendor in ["Apple"] and device_type == "Unknown Device":
            device_type = "Apple Device"
            confidence = "medium"
        elif vendor in ["Samsung", "LG", "Sony"] and device_type == "Unknown Device":
            device_type = "Smart TV / Electronics"
            confidence = "low"
        elif vendor == "Raspberry Pi":
            device_type = "Raspberry Pi"
            confidence = "high"
        elif vendor in ["Philips Hue"]:
            device_type = "Smart Home Hub"
            confidence = "high"
        elif vendor == "Roku":
            device_type = "Roku Streaming Device"
            confidence = "high"
    
    # IoT device detection
    if len(open_ports) <= 2 and device_type == "Unknown Device":
        if 80 in port_set or 23 in port_set:
            device_type = "IoT Device"
            confidence = "low"
            details.append("Minimal ports, possibly IoT")
    
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "device_type": device_type,
        "confidence": confidence,
        "details": details,
        "open_ports": open_ports,
        "os_guess": os_guess,
    }


def extract_vendor_from_scan_data(deep_scan: dict, http_info: dict = None, banners: dict = None) -> str:
    """Extract vendor from deep scan results, HTTP headers, and banners."""
    if http_info and http_info.get("vendor"):
        return http_info["vendor"]
    
    server_vendors = {
        "mikrotik": "MikroTik", "tp-link": "TP-Link", "tplink": "TP-Link",
        "netgear": "NETGEAR", "linksys": "Linksys", "asus": "ASUS",
        "d-link": "D-Link", "dlink": "D-Link", "ubnt": "Ubiquiti",
        "ubiquiti": "Ubiquiti", "synology": "Synology", "qnap": "QNAP",
        "hikvision": "Hikvision", "dahua": "Dahua", "cisco": "Cisco",
        "huawei": "Huawei", "zyxel": "ZyXEL", "buffalo": "Buffalo",
        "western digital": "Western Digital", "wd": "Western Digital",
        "sonos": "Sonos", "philips": "Philips", "nest": "Google Nest",
        "ring": "Ring", "ecobee": "Ecobee", "roku": "Roku",
        "amazon": "Amazon", "apple": "Apple",
    }
    
    # Check HTTP server/title
    server = http_info.get("server", "").lower() if http_info else ""
    title = http_info.get("title", "").lower() if http_info else ""
    
    for pattern, vendor_name in server_vendors.items():
        if pattern in server or pattern in title:
            return vendor_name
    
    # Check banners
    if banners:
        for port, banner in banners.items():
            banner_lower = banner.lower()
            for pattern, vendor_name in server_vendors.items():
                if pattern in banner_lower:
                    return vendor_name
            if "dropbear" in banner_lower:
                return "Embedded Device"
    
    # Check deep scan findings
    if deep_scan:
        findings_str = str(deep_scan.get("findings", [])).lower()
        for pattern, vendor_name in server_vendors.items():
            if pattern in findings_str:
                return vendor_name
    
    return "Unknown"



# Enhanced device identification

DEVICE_PORT_SIGNATURES = {
    "Apple TV": {3689, 7000, 49152},
    "Sonos Speaker": {1400, 1443, 3400, 3401, 3500, 9000},
    "Philips Hue": {80, 443, 1900},
    "Nest Device": {443, 11095},
    "Ring Device": {443, 8883},
    "Amazon Echo": {4070, 55442, 55443},
    "Google Home": {8008, 8009, 8443, 9000},
    "Roku": {8060, 8443},
    "Fire TV": {8008, 8009},
    "Chromecast": {8008, 8009, 8443},
    "Smart Bulb": {80, 9999},
    "Raspberry Pi": {22, 80, 443},
}


def identify_from_http(ip: str, port: int = 80) -> Dict[str, str]:
    """Identify device from HTTP headers and content."""
    info = {}
    
    try:
        req = urllib.request.Request(f"http://{ip}:{port}/")
        req.add_header("User-Agent", "HomeGuard/1.0")
        
        with urllib.request.urlopen(req, timeout=2) as resp:
            # Server header analysis
            server = resp.headers.get("Server", "")
            if server:
                info["server"] = server
                server_lower = server.lower()
                
                if "synology" in server_lower:
                    info["device_type"] = "Synology NAS"
                    info["confidence"] = "high"
                elif "qnap" in server_lower:
                    info["device_type"] = "QNAP NAS"
                    info["confidence"] = "high"
                elif "apache" in server_lower or "nginx" in server_lower:
                    info["device_type"] = "Web Server"
                    info["confidence"] = "medium"
                elif "mikrotik" in server_lower:
                    info["device_type"] = "MikroTik Router"
                    info["confidence"] = "high"
            
            # Page title analysis
            html = resp.read(8192).decode(errors="ignore")
            title_match = re.search(r"<title>([^<]+)</title>", html, re.I)
            if title_match:
                title = title_match.group(1).strip()
                info["title"] = title
                title_lower = title.lower()
                
                # Device hints from title
                if "router" in title_lower or "gateway" in title_lower:
                    info["device_type"] = info.get("device_type", "Router")
                    info["confidence"] = "high"
                elif "camera" in title_lower or "ipcam" in title_lower:
                    info["device_type"] = "IP Camera"
                    info["confidence"] = "high"
                elif "printer" in title_lower:
                    info["device_type"] = "Printer"
                    info["confidence"] = "high"
                elif "nas" in title_lower or "storage" in title_lower:
                    info["device_type"] = "NAS"
                    info["confidence"] = "high"
                elif "home assistant" in title_lower:
                    info["device_type"] = "Home Assistant"
                    info["confidence"] = "high"
                elif "pi-hole" in title_lower:
                    info["device_type"] = "Pi-hole"
                    info["confidence"] = "high"
                elif "unifi" in title_lower:
                    info["device_type"] = "UniFi Controller"
                    info["confidence"] = "high"
                
    except Exception:
        pass
    
    return info


def calculate_device_confidence(indicators: Dict) -> Tuple[str, str]:
    """Calculate device type with confidence score."""
    scores = {}
    
    # Port signature matching: +30 points per matching port
    if "port_matches" in indicators:
        for device_type, matched_ports in indicators["port_matches"].items():
            match_ratio = len(matched_ports) / len(DEVICE_PORT_SIGNATURES.get(device_type, {1}))
            scores[device_type] = match_ratio * 60
    
    # Vendor match: +50 points
    if "vendor" in indicators and indicators["vendor"] != "Unknown":
        vendor = indicators["vendor"]
        # Direct vendor to device type mapping
        vendor_devices = {
            "Apple": "Apple Device",
            "Sonos": "Sonos Speaker",
            "Roku": "Roku",
            "Philips": "Philips Device",
            "Nest": "Nest Device",
            "Ring": "Ring Device",
            "Amazon": "Amazon Device",
            "Google": "Google Device",
            "Synology": "Synology NAS",
            "QNAP": "QNAP NAS",
            "Raspberry Pi": "Raspberry Pi",
        }
        for vendor_key, device_type in vendor_devices.items():
            if vendor_key.lower() in vendor.lower():
                scores[device_type] = scores.get(device_type, 0) + 50
    
    # HTTP identification: +70 points (high confidence)
    if "http_device_type" in indicators:
        device_type = indicators["http_device_type"]
        http_conf = indicators.get("http_confidence", "medium")
        points = {"high": 70, "medium": 50, "low": 30}.get(http_conf, 30)
        scores[device_type] = scores.get(device_type, 0) + points
    
    # Banner match: +60 points
    if "banner_device_type" in indicators:
        device_type = indicators["banner_device_type"]
        scores[device_type] = scores.get(device_type, 0) + 60
    
    # Get highest score
    if scores:
        best_match = max(scores.items(), key=lambda x: x[1])
        device_type, score = best_match
        
        if score >= 80:
            return device_type, "high"
        elif score >= 50:
            return device_type, "medium"
        else:
            return device_type, "low"
    
    return "Unknown Device", "low"


def identify_device_enhanced(ip: str, mac: str, open_ports: List[int], os_guess: str, 
                            hostname: Optional[str] = None, banners: Optional[Dict] = None,
                            use_llm: bool = False, backend_url: Optional[str] = None) -> Dict:
    """Enhanced device identification with multiple methods."""
    indicators = {}
    
    # Get vendor from MAC
    vendor = get_mac_vendor(mac)
    if vendor != "Unknown":
        indicators["vendor"] = vendor
    
    port_set = set(open_ports)
    
    # PRIORITY 1: Check if it's a router/gateway (most important)
    if ip.endswith(".1") or ip.endswith(".254"):
        if any(p in port_set for p in [80, 443, 53, 8080]):
            return {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "device_type": "Router/Gateway",
                "confidence": "high",
                "indicators": {"gateway_ip": True, "router_ports": True},
                "open_ports": open_ports,
                "os_guess": os_guess,
                "hostname": hostname,
            }
    
    # Check port signatures
    port_matches = {}
    for device_type, signature_ports in DEVICE_PORT_SIGNATURES.items():
        matched = port_set & signature_ports
        if matched:
            port_matches[device_type] = matched
    if port_matches:
        indicators["port_matches"] = port_matches
    
    # Quick identification for specific port combinations
    if 5000 in port_set or 5001 in port_set:
        indicators["http_device_type"] = "NAS / Storage Device"
        indicators["http_confidence"] = "medium"
    elif 62078 in port_set:
        indicators["http_device_type"] = "Apple Device"
        indicators["http_confidence"] = "high"
    elif 8008 in port_set:
        indicators["http_device_type"] = "Chromecast / Smart Display"
        indicators["http_confidence"] = "high"
    elif 9000 in port_set:
        indicators["http_device_type"] = "Sonos Speaker"
        indicators["http_confidence"] = "high"
    
    # HTTP identification on standard ports
    if 80 in port_set or 8080 in port_set:
        http_port = 80 if 80 in port_set else 8080
        http_info = identify_from_http(ip, http_port)
        if http_info.get("device_type"):
            indicators["http_device_type"] = http_info["device_type"]
            indicators["http_confidence"] = http_info.get("confidence", "medium")
    
    # Banner analysis
    if banners:
        for port, banner in banners.items():
            if not banner:  # Skip None or empty banners
                continue
            banner_lower = banner.lower()
            if "dropbear" in banner_lower:
                indicators["banner_device_type"] = "Embedded Device/Router"
            elif "mikrotik" in banner_lower:
                indicators["banner_device_type"] = "MikroTik Router"
            elif "ubnt" in banner_lower or "ubiquiti" in banner_lower:
                indicators["banner_device_type"] = "Ubiquiti Device"
            elif "synology" in banner_lower:
                indicators["banner_device_type"] = "Synology NAS"
            elif "qnap" in banner_lower:
                indicators["banner_device_type"] = "QNAP NAS"
    
    # Calculate final device type and confidence
    device_type, confidence = calculate_device_confidence(indicators)
    
    # If still unknown and LLM enabled, use AI identification
    if device_type == "Unknown Device" and use_llm and backend_url:
        llm_result = _identify_with_llm(ip, mac, open_ports, banners or {}, backend_url)
        if llm_result and llm_result.get("device_type") != "Unknown Device":
            device_type = llm_result["device_type"]
            confidence = llm_result.get("confidence", "medium")
            indicators["llm_identification"] = llm_result
    
    # Fallback to original logic if still unknown
    if device_type == "Unknown Device":
        result = identify_device_type(ip, mac, open_ports, os_guess)
        device_type = result["device_type"]
        confidence = result["confidence"]
    
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "device_type": device_type,
        "confidence": confidence,
        "indicators": indicators,
        "open_ports": open_ports,
        "os_guess": os_guess,
        "hostname": hostname,
    }


def _identify_with_llm(ip: str, mac: str, open_ports: List[int], banners: Dict, backend_url: str) -> Optional[Dict]:
    """Use LLM backend to identify device."""
    try:
        import json
        import urllib.request
        
        data = {
            "ip": ip,
            "mac": mac,
            "open_ports": open_ports,
            "banners": banners,
            "http_info": {}
        }
        
        req = urllib.request.Request(
            f"{backend_url}/api/identify/device",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            # Extract identification from response
            return result.get("identification", result)
            
    except Exception:
        return None
