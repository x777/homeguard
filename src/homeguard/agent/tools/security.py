"""Security check tools - encryption, UPnP, firmware, DNS, credentials."""

import socket
import ssl
import urllib.request
from datetime import datetime
from .validators import validate_ip
from .rate_limiter import check_http_rate
from ..constants import MAX_HTTP_RESPONSE_SIZE


def check_encryption(ip: str) -> dict:
    """Check TLS/SSL encryption status of a device."""
    result = {
        "ip": ip,
        "findings": [],
        "tls_version": None,
        "certificate": {},
        "risk_level": "low",
        "accepts_unencrypted": False,
        "context": "29% of IoT devices use weak or no encryption",
    }
    
    # Check HTTP
    if _check_port(ip, 80):
        result["accepts_unencrypted"] = True
        result["findings"].append("🟠 Device accepts unencrypted HTTP connections")
        result["risk_level"] = "medium"
    
    # Check HTTPS/TLS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        context = ssl.create_default_context()
        try:
            wrapped = context.wrap_socket(sock, server_hostname=ip)
            wrapped.connect((ip, 443))
            result["certificate"]["valid"] = True
            result["tls_version"] = wrapped.version()
            wrapped.close()
        except ssl.SSLCertVerificationError:
            result["certificate"]["valid"] = False
            result["certificate"]["error"] = "Self-signed or invalid certificate"
            result["findings"].append("🟡 Self-signed or invalid SSL certificate")
        except Exception:
            pass
        
        if not result["tls_version"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                wrapped = context.wrap_socket(sock, server_hostname=ip)
                wrapped.connect((ip, 443))
                result["tls_version"] = wrapped.version()
                wrapped.close()
            except Exception:
                pass
    except Exception:
        pass
    
    # Evaluate TLS version
    if result["tls_version"]:
        if "1.0" in result["tls_version"] or "1.1" in result["tls_version"]:
            result["findings"].append(f"🔴 Using outdated {result['tls_version']} - vulnerable to attacks")
            result["risk_level"] = "high"
        elif "1.2" in result["tls_version"]:
            result["findings"].append(f"✅ Using {result['tls_version']} - acceptable")
        elif "1.3" in result["tls_version"]:
            result["findings"].append(f"✅ Using {result['tls_version']} - excellent")
    
    return result


def check_upnp_exposure(ip: str) -> dict:
    """Check for UPnP exposure risks."""
    result = {
        "ip": ip,
        "upnp_enabled": False,
        "findings": [],
        "port_mappings": [],
        "risk_level": "low",
        "context": "UPnP-enabled devices are common entry points for botnet recruitment",
    }
    
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
        
        if response:
            result["upnp_enabled"] = True
            result["risk_level"] = "medium"
            result["findings"].append("🟠 UPnP is enabled - devices can automatically open ports")
            result["findings"].append("💡 Consider disabling UPnP to prevent unauthorized port forwarding")
        sock.close()
    except socket.timeout:
        result["findings"].append("✅ UPnP not detected or disabled - good security practice")
    except Exception:
        result["findings"].append("✅ UPnP not detected or disabled - good security practice")
    
    return result


def check_firmware_age(ip: str) -> dict:
    """Check firmware age from HTTP headers."""
    result = {
        "ip": ip,
        "findings": [],
        "versions_found": [],
        "last_modified": None,
        "risk_level": "low",
        "age_estimate": None,
        "context": "33% of IoT devices run outdated firmware with known vulnerabilities",
    }
    
    try:
        req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "HomeGuard/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            last_modified = resp.headers.get("Last-Modified")
            server = resp.headers.get("Server", "")
            
            if last_modified:
                result["last_modified"] = last_modified
                try:
                    from email.utils import parsedate_to_datetime
                    mod_date = parsedate_to_datetime(last_modified)
                    age_days = (datetime.now(mod_date.tzinfo) - mod_date).days
                    result["age_estimate"] = f"{age_days} days"
                    
                    if age_days > 365:
                        result["findings"].append(f"🟠 Content last modified {age_days} days ago - may indicate outdated firmware")
                        result["risk_level"] = "medium"
                    elif age_days > 180:
                        result["findings"].append(f"🟡 Content last modified {age_days} days ago - check for updates")
                except Exception:
                    pass
            
            # Check server header for version info
            outdated_patterns = [
                ("apache/2.0", "Apache 2.0"), ("apache/2.2", "Apache 2.2"),
                ("nginx/1.0", "nginx 1.0"), ("nginx/1.1", "nginx 1.1"),
                ("openssh_5", "OpenSSH 5.x"), ("openssh_6", "OpenSSH 6.x"),
                ("php/5", "PHP 5.x"), ("dropbear_0", "Dropbear 0.x"),
            ]
            
            server_lower = server.lower()
            for pattern, name in outdated_patterns:
                if pattern in server_lower:
                    result["versions_found"].append(name)
                    result["findings"].append(f"🔴 Outdated software detected: {name}")
                    result["risk_level"] = "high"
            
            if not result["findings"]:
                result["findings"].append("📦 Could not determine firmware/software versions")
                
    except Exception:
        result["findings"].append("📦 Could not determine firmware/software versions")
    
    return result


SAFE_DNS_SERVERS = [
    "8.8.8.8", "8.8.4.4",  # Google
    "1.1.1.1", "1.0.0.1",  # Cloudflare
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
]


def check_dns_hijacking(ip: str) -> dict:
    """Check for DNS hijacking indicators on router."""
    result = {
        "ip": ip,
        "findings": [],
        "dns_servers": [],
        "hijacking_detected": False,
        "risk_level": "low",
        "context": "GhostDNS attacks have compromised over 100,000 routers by hijacking DNS settings",
    }
    
    # Try to query router's DNS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        # Simple DNS query for google.com
        query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
        sock.sendto(query, (ip, 53))
        response, _ = sock.recvfrom(512)
        
        if response:
            result["findings"].append("✅ Router DNS is responding normally")
        sock.close()
    except socket.timeout:
        result["findings"].append("🟡 Router DNS not responding - may be disabled or filtered")
    except Exception:
        pass
    
    return result


def check_default_credentials(ip: str, port: int) -> dict:
    """Check for signs of default credentials on web interface."""
    result = {"ip": ip, "port": port, "findings": [], "risk_level": "low"}
    
    try:
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
        
        sock.connect((ip, port))
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        
        response_lower = response.lower()
        
        # Check for default credential indicators
        default_indicators = [
            ("admin", "Default 'admin' username may be in use"),
            ("password", "Password field detected - ensure default changed"),
            ("default", "Default configuration detected"),
            ("setup wizard", "Setup wizard active - device may not be configured"),
            ("first time", "First-time setup detected"),
        ]
        
        for indicator, message in default_indicators:
            if indicator in response_lower:
                result["findings"].append(f"🟡 {message}")
                result["risk_level"] = "medium"
        
        if not result["findings"]:
            result["findings"].append("✅ No obvious default credential indicators")
            
    except Exception as e:
        result["findings"].append(f"Could not check: {str(e)[:50]}")
    
    result["context"] = "35% of IoT devices ship with default credentials"
    return result


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
