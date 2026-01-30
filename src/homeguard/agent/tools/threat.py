"""Threat intelligence tools - CVE lookup, threat intel checks."""

import asyncio
from .definitions import ToolResult


async def lookup_cve_async(keyword: str, backend_url: str) -> list:
    """Search CVE database via backend."""
    import httpx
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{backend_url}/api/cve/search/{keyword}")
            response.raise_for_status()
            return response.json().get("results", [])
        except Exception:
            return []


async def check_threat_intel_async(ip: str, check_type: str, backend_url: str, vendor: str = None) -> dict:
    """Check against threat intelligence feeds via backend."""
    import httpx
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            if check_type == "vendor" and vendor:
                response = await client.get(f"{backend_url}/api/threat/vendor/{vendor}")
            elif check_type == "iot" and vendor:
                response = await client.get(f"{backend_url}/api/threat/iot/{vendor}")
            elif check_type == "dns":
                response = await client.get(f"{backend_url}/api/threat/dns/{ip}")
            else:
                response = await client.get(f"{backend_url}/api/threat/ip/{ip}")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e), "ip": ip}


def lookup_cve(keyword: str, backend_url: str) -> ToolResult:
    """Search CVE database."""
    if not backend_url:
        return ToolResult(success=False, data=None, error="Backend URL not configured")
    
    try:
        results = asyncio.get_event_loop().run_until_complete(
            lookup_cve_async(keyword, backend_url)
        )
    except RuntimeError:
        results = asyncio.run(lookup_cve_async(keyword, backend_url))
    
    return ToolResult(success=True, data={"keyword": keyword, "cves": results})


def check_threat_intel(ip: str, check_type: str, backend_url: str, vendor: str = None) -> ToolResult:
    """Check threat intelligence feeds."""
    if not backend_url:
        return ToolResult(success=False, data=None, error="Backend URL not configured")
    
    try:
        result = asyncio.get_event_loop().run_until_complete(
            check_threat_intel_async(ip, check_type, backend_url, vendor)
        )
    except RuntimeError:
        result = asyncio.run(check_threat_intel_async(ip, check_type, backend_url, vendor))
    
    return ToolResult(success=True, data=result)
