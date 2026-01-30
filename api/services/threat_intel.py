"""Threat Intelligence Pipeline - aggregates multiple threat feeds."""

import httpx
import os
from typing import Optional
from datetime import datetime, timedelta
import asyncio

# API Keys (optional - some services have free tiers)
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_KEY", "")
VARIOT_KEY = os.getenv("VARIOT_KEY", "")  # VARIoT IoT vulnerability DB

# Cache for rate limiting
_cache = {}
CACHE_TTL = 3600  # 1 hour


def _get_cached(key: str) -> Optional[dict]:
    """Get cached result if not expired."""
    if key in _cache:
        data, timestamp = _cache[key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_TTL):
            return data
    return None


def _set_cached(key: str, data: dict):
    """Cache result."""
    _cache[key] = (data, datetime.now())


async def check_ip_reputation(ip: str) -> dict:
    """Check IP reputation across multiple sources."""
    cache_key = f"ip:{ip}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    result = {
        "ip": ip,
        "is_malicious": False,
        "risk_score": 0,
        "sources": [],
        "findings": [],
    }

    # Run checks in parallel
    checks = []
    if ABUSEIPDB_KEY:
        checks.append(_check_abuseipdb(ip))
    if SHODAN_KEY:
        checks.append(_check_shodan(ip))
    
    # Always check free sources
    checks.append(_check_blocklist_de(ip))
    
    if checks:
        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                result["sources"].append(r.get("source", "unknown"))
                if r.get("is_malicious"):
                    result["is_malicious"] = True
                    result["findings"].extend(r.get("findings", []))
                result["risk_score"] = max(result["risk_score"], r.get("risk_score", 0))

    _set_cached(cache_key, result)
    return result


async def _check_abuseipdb(ip: str) -> dict:
    """Check IP against AbuseIPDB."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            
            abuse_score = data.get("abuseConfidenceScore", 0)
            return {
                "source": "AbuseIPDB",
                "is_malicious": abuse_score > 50,
                "risk_score": abuse_score,
                "findings": [f"AbuseIPDB confidence: {abuse_score}%"] if abuse_score > 0 else [],
            }
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


async def _check_shodan(ip: str) -> dict:
    """Check IP against Shodan for exposed services."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_KEY},
            )
            if response.status_code == 404:
                return {"source": "Shodan", "is_malicious": False, "risk_score": 0}
            
            response.raise_for_status()
            data = response.json()
            
            findings = []
            risk_score = 0
            
            # Check for vulnerabilities
            vulns = data.get("vulns", [])
            if vulns:
                findings.append(f"Shodan found {len(vulns)} vulnerabilities")
                risk_score = min(100, len(vulns) * 20)
            
            # Check for exposed services
            ports = data.get("ports", [])
            dangerous_ports = [23, 445, 3389, 5900]  # Telnet, SMB, RDP, VNC
            exposed = [p for p in ports if p in dangerous_ports]
            if exposed:
                findings.append(f"Dangerous ports exposed: {exposed}")
                risk_score = max(risk_score, 60)
            
            return {
                "source": "Shodan",
                "is_malicious": risk_score > 50,
                "risk_score": risk_score,
                "findings": findings,
                "ports": ports,
                "vulns": vulns[:5] if vulns else [],
            }
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}


async def _check_blocklist_de(ip: str) -> dict:
    """Check IP against blocklist.de (free)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check if IP is in blocklist
            response = await client.get(
                f"http://api.blocklist.de/api.php?ip={ip}"
            )
            text = response.text.strip()
            
            is_listed = "attacks" in text.lower() or text.startswith("<")
            return {
                "source": "blocklist.de",
                "is_malicious": is_listed,
                "risk_score": 70 if is_listed else 0,
                "findings": ["Listed in blocklist.de"] if is_listed else [],
            }
    except Exception:
        return {"source": "blocklist.de", "is_malicious": False, "risk_score": 0}


async def check_dns_reputation(dns_ip: str) -> dict:
    """Check if a DNS server IP is known malicious."""
    cache_key = f"dns:{dns_ip}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    result = {
        "dns_ip": dns_ip,
        "is_malicious": False,
        "is_safe": False,
        "findings": [],
    }

    # Known safe DNS servers
    safe_dns = {
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        "1.1.1.1": "Cloudflare DNS",
        "1.0.0.1": "Cloudflare DNS",
        "9.9.9.9": "Quad9 DNS",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

    if dns_ip in safe_dns:
        result["is_safe"] = True
        result["findings"].append(f"✅ Known safe DNS: {safe_dns[dns_ip]}")
    else:
        # Check IP reputation
        ip_rep = await check_ip_reputation(dns_ip)
        if ip_rep.get("is_malicious"):
            result["is_malicious"] = True
            result["findings"].append("🔴 DNS server IP flagged as malicious")
            result["findings"].extend(ip_rep.get("findings", []))
        else:
            result["findings"].append("🟡 Unknown DNS server - verify with ISP")

    _set_cached(cache_key, result)
    return result


async def get_vendor_advisories(vendor: str) -> list[dict]:
    """Get recent security advisories for a vendor."""
    cache_key = f"vendor:{vendor.lower()}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    advisories = []
    
    # Search VARIoT IoT database first (IoT-focused)
    variot_results = await search_variot_exploits(vendor)
    advisories.extend(variot_results)
    
    # Also search NVD for CVEs
    from .cve import search_cve
    cves = await search_cve(vendor)
    
    # Filter to high severity
    for cve in cves:
        if cve.get("severity") in ["HIGH", "CRITICAL"]:
            advisories.append({
                "source": "NVD",
                "cve_id": cve.get("id"),
                "severity": cve.get("severity"),
                "score": cve.get("score"),
                "description": cve.get("description"),
            })

    _set_cached(cache_key, advisories)
    return advisories


async def search_variot_exploits(keyword: str) -> list[dict]:
    """Search VARIoT IoT exploits database."""
    cache_key = f"variot:{keyword.lower()}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    results = []
    headers = {}
    if VARIOT_KEY:
        headers["Authorization"] = f"Token {VARIOT_KEY}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Search exploits
            response = await client.get(
                "https://www.variotdbs.pl/api/exploits/",
                params={"jsonld": "false"},
                headers=headers,
            )
            
            if response.status_code == 200:
                data = response.json()
                exploits = data.get("results", [])
                
                # Filter by keyword in title/description
                keyword_lower = keyword.lower()
                for exploit in exploits[:100]:  # Limit to first 100
                    title = str(exploit.get("title", "") or "").lower()
                    desc = exploit.get("description", "")
                    desc = str(desc) if not isinstance(desc, dict) else str(desc.get("value", ""))
                    desc = desc.lower()
                    
                    if keyword_lower in title or keyword_lower in desc:
                        results.append({
                            "source": "VARIoT",
                            "id": exploit.get("id"),
                            "title": str(exploit.get("title", "") or "")[:100],
                            "cve_id": exploit.get("cve_id"),
                            "type": exploit.get("type", "Unknown"),
                            "severity": "high",  # Exploits are high severity by nature
                        })
                        
                        if len(results) >= 5:  # Limit results
                            break
    except Exception as e:
        results.append({"error": str(e)})

    _set_cached(cache_key, results)
    return results


async def search_variot_vulns(keyword: str) -> list[dict]:
    """Search VARIoT IoT vulnerabilities database."""
    cache_key = f"variot_vuln:{keyword.lower()}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    results = []
    headers = {}
    if VARIOT_KEY:
        headers["Authorization"] = f"Token {VARIOT_KEY}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://www.variotdbs.pl/api/vulns/",
                params={"jsonld": "false"},
                headers=headers,
            )
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("results", [])
                
                keyword_lower = keyword.lower()
                for vuln in vulns[:100]:
                    title = str(vuln.get("title", "") or "").lower()
                    desc = vuln.get("description", "")
                    desc = str(desc) if not isinstance(desc, dict) else str(desc.get("value", ""))
                    desc = desc.lower()
                    
                    if keyword_lower in title or keyword_lower in desc:
                        results.append({
                            "source": "VARIoT",
                            "id": vuln.get("id"),
                            "cve_id": vuln.get("cve_id"),
                            "title": str(vuln.get("title", "") or "")[:100],
                            "severity": vuln.get("severity", "unknown"),
                            "cvss_score": vuln.get("cvss_score"),
                        })
                        
                        if len(results) >= 5:
                            break
    except Exception as e:
        results.append({"error": str(e)})

    _set_cached(cache_key, results)
    return results


async def get_iot_exploits_for_device(vendor: str, model: str = None) -> list[dict]:
    """Get known IoT exploits for a specific device."""
    search_term = f"{vendor} {model}" if model else vendor
    
    # Search both exploits and vulnerabilities
    exploits = await search_variot_exploits(search_term)
    vulns = await search_variot_vulns(search_term)
    
    return {
        "vendor": vendor,
        "model": model,
        "exploits": exploits,
        "vulnerabilities": vulns,
        "total_threats": len(exploits) + len(vulns),
    }


async def analyze_network_threats(scan_data: dict) -> dict:
    """Analyze a network scan for threats using threat intelligence."""
    result = {
        "threat_level": "low",
        "findings": [],
        "recommendations": [],
        "device_threats": [],
    }

    devices = scan_data.get("devices", [])
    
    for device in devices:
        device_result = {
            "ip": device.get("ip"),
            "device_type": device.get("device_type", "Unknown"),
            "threats": [],
        }

        # Check for dangerous open ports
        open_ports = device.get("open_ports", [])
        port_nums = [p.get("port") for p in open_ports if p.get("port")]
        
        dangerous = {
            23: "Telnet - unencrypted remote access",
            445: "SMB - ransomware target",
            3389: "RDP - common attack vector",
            5900: "VNC - remote desktop exposure",
            1433: "MSSQL - database exposure",
            3306: "MySQL - database exposure",
            27017: "MongoDB - often misconfigured",
        }
        
        for port, desc in dangerous.items():
            if port in port_nums:
                device_result["threats"].append({
                    "type": "dangerous_port",
                    "port": port,
                    "description": desc,
                    "severity": "high",
                })
                result["threat_level"] = "high"

        # Get vendor advisories if vendor known
        vendor = device.get("vendor")
        if vendor and vendor != "Unknown":
            advisories = await get_vendor_advisories(vendor)
            if advisories:
                device_result["vendor_advisories"] = advisories[:3]
                device_result["threats"].append({
                    "type": "vendor_vulnerabilities",
                    "count": len(advisories),
                    "severity": "medium",
                })

        if device_result["threats"]:
            result["device_threats"].append(device_result)

    # Generate recommendations
    if result["threat_level"] == "high":
        result["recommendations"].extend([
            "Immediately close or firewall dangerous ports",
            "Enable network segmentation for IoT devices",
            "Update all device firmware",
        ])
    
    result["findings"].append(f"Analyzed {len(devices)} devices")
    result["findings"].append(f"Found {len(result['device_threats'])} devices with threats")

    return result
