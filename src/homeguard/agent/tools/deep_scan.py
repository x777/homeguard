"""Deep scan tools for routers, IoT, storage, and unknown devices."""

import socket
import re
import urllib.request
from .validators import validate_ip, validate_port
from .rate_limiter import check_scan_rate, check_http_rate
from ..constants import MAX_HTTP_RESPONSE_SIZE, BANNER_GRAB_TIMEOUT_SECONDS

# Port configurations with severity levels
PORT_CONFIGS = {
    "router": {
        23: ("Telnet", "CRITICAL - Telnet is unencrypted, disable immediately", "critical"),
        80: ("HTTP Admin", "Consider HTTPS-only access", "medium"),
        443: ("HTTPS Admin", "Good - encrypted admin access", "low"),
        53: ("DNS", "Router providing DNS - check for DNS rebinding protection", "low"),
        67: ("DHCP", "DHCP server active", "low"),
        161: ("SNMP", "HIGH - SNMP can leak network info, ensure SNMPv3 or disable", "high"),
        1900: ("UPnP", "MEDIUM - UPnP can be exploited, consider disabling", "medium"),
        5000: ("UPnP/SSDP", "UPnP discovery active", "medium"),
        8080: ("Alt HTTP", "Alternative admin port - ensure secured", "medium"),
        8443: ("Alt HTTPS", "Alternative secure admin port", "low"),
        7547: ("TR-069", "CRITICAL - ISP remote management, potential backdoor", "critical"),
    },
    "iot": {
        23: ("Telnet", "CRITICAL - Many IoT devices have default telnet credentials", "critical"),
        80: ("HTTP", "Web interface - check for firmware updates", "medium"),
        443: ("HTTPS", "Secure web interface", "low"),
        554: ("RTSP", "Video streaming - ensure authentication enabled", "high"),
        1883: ("MQTT", "CRITICAL - Unencrypted MQTT, use 8883 with TLS", "critical"),
        8883: ("MQTT-TLS", "Good - encrypted MQTT", "low"),
        5683: ("CoAP", "IoT protocol - check authentication", "medium"),
        8080: ("Alt HTTP", "Alternative web port", "medium"),
        9999: ("Common IoT", "Generic IoT port - investigate", "medium"),
        49152: ("UPnP", "UPnP port - common on IoT", "medium"),
    },
    "storage": {
        21: ("FTP", "HIGH - FTP is unencrypted, use SFTP instead", "high"),
        22: ("SSH/SFTP", "Good - secure file transfer", "low"),
        80: ("HTTP Admin", "Web admin interface", "medium"),
        443: ("HTTPS Admin", "Secure web admin", "low"),
        139: ("NetBIOS", "Windows sharing - legacy protocol", "medium"),
        445: ("SMB", "File sharing - ensure SMBv3, disable SMBv1", "high"),
        548: ("AFP", "Apple Filing Protocol", "low"),
        2049: ("NFS", "Network File System - check export permissions", "high"),
        5000: ("Synology DSM", "Synology admin port", "medium"),
        5001: ("Synology DSM SSL", "Synology secure admin", "low"),
        8080: ("QNAP QTS", "QNAP admin port", "medium"),
    },
}


def _scan_ports_from_config(ip: str, port_config: dict) -> tuple[list, list]:
    """Generic port scanner using configuration."""
    open_ports, findings = [], []
    for port, (service, note, severity) in port_config.items():
        if _check_port(ip, port):
            open_ports.append(port)
            findings.append({"port": port, "service": service, "note": note, "severity": severity})
    return open_ports, findings


def deep_scan_router(ip: str) -> dict:
    """Deep scan a router/gateway device."""
    valid, error = validate_ip(ip)
    if not valid:
        return {"ip": ip, "error": error, "open_ports": [], "findings": []}
    
    if not check_scan_rate(ip):
        return {"ip": ip, "error": "Rate limit exceeded", "open_ports": [], "findings": []}
    
    open_ports, findings = _scan_ports_from_config(ip, PORT_CONFIGS["router"])
    http_info = {}
    
    admin_check = _check_http_admin(ip)
    if admin_check:
        findings.append(admin_check)
        for key in ["server", "title", "vendor"]:
            if admin_check.get(key):
                http_info[key] = admin_check[key]
    
    return {
        "ip": ip,
        "device_type": "router",
        "open_ports": open_ports,
        "findings": findings,
        "http_info": http_info,
        "recommendations": _get_router_recommendations(findings),
    }


def deep_scan_iot(ip: str) -> dict:
    """Deep scan an IoT device."""
    open_ports, findings = _scan_ports_from_config(ip, PORT_CONFIGS["iot"])
    
    return {
        "ip": ip,
        "device_type": "iot",
        "open_ports": open_ports,
        "findings": findings,
        "recommendations": _get_iot_recommendations(findings),
    }


def deep_scan_storage(ip: str) -> dict:
    """Deep scan a NAS/storage device."""
    open_ports, findings = _scan_ports_from_config(ip, PORT_CONFIGS["storage"])
    
    return {
        "ip": ip,
        "device_type": "storage",
        "open_ports": open_ports,
        "findings": findings,
        "recommendations": _get_storage_recommendations(findings),
    }


def probe_unknown_device(ip: str, known_ports: list = None) -> dict:
    """Deep probe to identify an unknown device."""
    result = {
        "ip": ip,
        "findings": [],
        "possible_type": "Unknown",
        "confidence": "low",
        "banners": {},
        "http_info": {},
    }
    
    probe_ports = {
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
        21: "FTP", 445: "SMB", 139: "NetBIOS", 2049: "NFS",
        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
        1883: "MQTT", 8883: "MQTT-TLS", 5353: "mDNS", 1900: "UPnP",
        554: "RTSP", 8008: "Chromecast", 9000: "Sonos",
        9100: "Print", 631: "IPP", 548: "AFP", 62078: "iPhone-Sync",
        3074: "Xbox", 9295: "PlayStation",
    }
    
    open_ports = []
    known_port_nums = set(known_ports or [])
    
    for port in known_port_nums:
        service = probe_ports.get(port, "Unknown")
        open_ports.append((port, service))
    
    for port, service in probe_ports.items():
        if port not in known_port_nums and _check_port(ip, port, timeout=0.5):
            open_ports.append((port, service))
    
    # Grab banners
    for port, _ in open_ports:
        if port in [21, 22, 23, 25, 110, 143]:
            banner = _grab_banner(ip, port)
            if banner:
                result["banners"][port] = banner
    
    result["open_ports"] = open_ports
    port_nums = [p for p, _ in open_ports]
    
    # Device type inference
    result["possible_type"], result["confidence"], finding = _infer_device_type(port_nums, result["banners"])
    if finding:
        result["findings"].append(finding)
    
    # HTTP fingerprinting
    if 80 in port_nums or 8080 in port_nums:
        http_port = 80 if 80 in port_nums else 8080
        result["http_info"] = _probe_http(ip, http_port) or {}
    
    if not result["findings"]:
        result["findings"].append("No identifying features found - device may be firewalled")
    
    return result


def detect_device_model(ip: str) -> dict:
    """Detect device model from HTTP pages and UPnP."""
    result = {"ip": ip, "model": None, "firmware": None, "source": None}
    
    # Try UPnP first
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: upnp:rootdevice\r\n\r\n"
        )
        sock.sendto(ssdp_request.encode(), (ip, 1900))
        response, _ = sock.recvfrom(4096)
        response = response.decode(errors="ignore")
        
        for line in response.split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                req = urllib.request.Request(location, headers={"User-Agent": "HomeGuard/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    xml = resp.read().decode(errors="ignore")
                    model_match = re.search(r"<modelName>([^<]+)</modelName>", xml)
                    if model_match:
                        result["model"] = model_match.group(1).strip()
                        result["source"] = "upnp"
                    firmware = re.search(r"<firmwareVersion>([^<]+)</firmwareVersion>", xml)
                    if firmware:
                        result["firmware"] = firmware.group(1).strip()
                break
        sock.close()
    except Exception:
        pass
    
    if result["model"]:
        return result
    
    # Try HTTP scraping
    model_patterns = [
        r"model[:\s]+([A-Z0-9]+-?[A-Z0-9]+)",
        r"(Archer\s*[A-Z0-9]+)", r"(RT-[A-Z0-9]+)", r"(WRT[A-Z0-9]+)",
        r"(R[0-9]{4})", r"(DIR-[0-9]+)", r"(DS[0-9]{3,})", r"(TS-[0-9]+)",
    ]
    
    try:
        req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "HomeGuard/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            html = resp.read().decode(errors="ignore")
            for pattern in model_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    result["model"] = match.group(1).strip()
                    result["source"] = "http"
                    break
            fw_match = re.search(r"firmware[:\s]*v?([0-9]+\.[0-9]+[^\s<\"']*)", html, re.IGNORECASE)
            if fw_match:
                result["firmware"] = fw_match.group(1).strip()
    except Exception:
        pass
    
    return result


# Helper functions

def _check_port(ip: str, port: int, timeout: float = 1) -> bool:
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port)) == 0
        sock.close()
        return result
    except Exception:
        return False


def _grab_banner(ip: str, port: int) -> str | None:
    """Grab banner from a service."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_GRAB_TIMEOUT_SECONDS)
        if sock.connect_ex((ip, port)) == 0:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return banner[:100] if banner else None
        sock.close()
    except Exception:
        pass
    return None


def _probe_http(ip: str, port: int) -> dict | None:
    """Probe HTTP for device identification."""
    try:
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        
        info = {}
        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                info["server"] = line.split(":", 1)[1].strip()
        
        if "<title>" in response.lower():
            start = response.lower().find("<title>") + 7
            end = response.lower().find("</title>")
            if end > start:
                info["title"] = response[start:end].strip()[:100]
        
        return info if info else None
    except Exception:
        return None


def _check_http_admin(ip: str) -> dict | None:
    """Check HTTP admin interface for common issues."""
    if not check_http_rate(ip):
        return None
    
    result = {"check": "http_auth"}
    
    try:
        req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "HomeGuard/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            response = resp.read(MAX_HTTP_RESPONSE_SIZE).decode(errors="ignore")
            response_lower = response.lower()
            
            server = resp.headers.get("Server", "")
            if server:
                result["server"] = server
            
            # Follow meta refresh
            if 'url=' in response_lower and len(response) < 500:
                start = response_lower.find('url=') + 4
                end = response_lower.find('"', start)
                if end == -1:
                    end = response_lower.find("'", start)
                if end > start:
                    redirect_path = response[start:end].strip()
                    if redirect_path and not redirect_path.startswith("http"):
                        path = redirect_path if redirect_path.startswith("/") else "/" + redirect_path
                        try:
                            req2 = urllib.request.Request(f"http://{ip}{path}", headers={"User-Agent": "HomeGuard/1.0"})
                            with urllib.request.urlopen(req2, timeout=3) as resp2:
                                response = resp2.read().decode(errors="ignore")
                                response_lower = response.lower()
                        except Exception:
                            pass
            
            if "<title>" in response_lower:
                start = response_lower.find("<title>") + 7
                end = response_lower.find("</title>")
                if end > start:
                    result["title"] = response[start:end].strip()[:100]
            
            vendor_urls = {
                "tp-link.com": "TP-Link", "netgear.com": "NETGEAR", "asus.com": "ASUS",
                "linksys.com": "Linksys", "dlink.com": "D-Link", "mikrotik.com": "MikroTik",
                "ubnt.com": "Ubiquiti", "ui.com": "Ubiquiti", "synology.com": "Synology", "qnap.com": "QNAP",
            }
            for url, vendor in vendor_urls.items():
                if url in response_lower:
                    result["vendor"] = vendor
                    break
            
            result["status"] = "WARNING - No authentication on admin page"
            
    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["status"] = "Password protected"
        else:
            result["status"] = f"HTTP {e.code}"
    except Exception:
        return None
    
    return result


def _infer_device_type(port_nums: list, banners: dict) -> tuple[str, str, str]:
    """Infer device type from ports and banners."""
    if 3389 in port_nums:
        return "Windows PC", "high", "RDP port open - likely Windows machine"
    if 548 in port_nums or 62078 in port_nums:
        return "Apple Device", "high", "Apple-specific ports detected"
    if 3306 in port_nums or 5432 in port_nums or 27017 in port_nums:
        return "Database Server", "high", "Database port exposed - security risk!"
    if 9100 in port_nums or 631 in port_nums:
        return "Printer", "high", "Printer ports detected"
    if 554 in port_nums:
        return "IP Camera", "high", "RTSP streaming port - likely camera"
    if 8008 in port_nums:
        return "Chromecast/Smart Display", "high", "Chromecast port detected"
    if 9000 in port_nums:
        return "Sonos Speaker", "medium", "Sonos control port detected"
    if 1883 in port_nums or 8883 in port_nums:
        return "IoT Hub/Device", "medium", "MQTT broker/client detected"
    if 3074 in port_nums:
        return "Xbox Console", "high", "Xbox Live port detected"
    if 9295 in port_nums:
        return "PlayStation Console", "medium", "PlayStation port detected"
    if 22 in port_nums and 443 in port_nums:
        return "Linux Server/Device", "medium", "SSH + HTTPS - likely Linux server with web service"
    if 445 in port_nums or 139 in port_nums:
        return "Windows PC or NAS", "medium", "Windows file sharing ports detected"
    
    # Check banners
    for port, banner in banners.items():
        if "dropbear" in banner.lower():
            return "Embedded/IoT Device", "medium", f"Port {port}: Dropbear SSH (embedded device)"
        if "mikrotik" in banner.lower():
            return "MikroTik Router", "high", f"Port {port}: MikroTik detected"
        if "ubnt" in banner.lower() or "ubiquiti" in banner.lower():
            return "Ubiquiti Device", "high", f"Port {port}: Ubiquiti detected"
    
    return "Unknown", "low", ""


def _get_router_recommendations(findings: list) -> list[str]:
    """Generate router-specific recommendations."""
    recs = []
    ports = [f.get("port") for f in findings if isinstance(f, dict) and f.get("port")]
    
    if 23 in ports:
        recs.append("🔴 CRITICAL: Disable Telnet immediately and use SSH instead")
    if 7547 in ports:
        recs.append("🔴 CRITICAL: TR-069 port open - contact ISP about disabling remote management")
    if 161 in ports:
        recs.append("🟠 HIGH: Disable SNMP or upgrade to SNMPv3 with authentication")
    if 1900 in ports or 5000 in ports:
        recs.append("🟡 MEDIUM: Consider disabling UPnP to prevent port forwarding exploits")
    if 80 in ports and 443 not in ports:
        recs.append("🟡 MEDIUM: Enable HTTPS for admin access and disable HTTP")
    
    recs.append("✅ Change default admin password if not already done")
    recs.append("✅ Keep router firmware updated")
    return recs


def _get_iot_recommendations(findings: list) -> list[str]:
    """Generate IoT-specific recommendations."""
    recs = []
    ports = [f.get("port") for f in findings if isinstance(f, dict) and f.get("port")]
    
    if 23 in ports:
        recs.append("🔴 CRITICAL: Disable Telnet - IoT devices are prime botnet targets")
    if 1883 in ports:
        recs.append("🔴 CRITICAL: Use MQTT over TLS (port 8883) instead of unencrypted MQTT")
    if 554 in ports:
        recs.append("🟠 HIGH: Ensure RTSP streaming requires authentication")
    
    recs.append("✅ Check for firmware updates regularly")
    recs.append("✅ Disable cloud features if not needed")
    recs.append("✅ Place IoT devices on a separate network/VLAN")
    return recs


def _get_storage_recommendations(findings: list) -> list[str]:
    """Generate storage-specific recommendations."""
    recs = []
    ports = [f.get("port") for f in findings if isinstance(f, dict) and f.get("port")]
    
    if 21 in ports:
        recs.append("🔴 CRITICAL: Disable FTP and use SFTP instead")
    if 445 in ports:
        recs.append("🟠 HIGH: Ensure SMBv1 is disabled, use SMBv3 only")
    if 139 in ports:
        recs.append("🟠 HIGH: Consider disabling NetBIOS if not needed")
    if 2049 in ports:
        recs.append("🟡 MEDIUM: Review NFS export permissions")
    
    recs.append("✅ Enable encryption for data at rest")
    recs.append("✅ Set up regular backup verification")
    recs.append("✅ Keep NAS firmware updated")
    return recs
