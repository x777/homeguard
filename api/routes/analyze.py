"""API routes for chat, CVE lookup, and threat intelligence."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.llm import chat_completion
from services.cve import search_cve, get_cve_by_id
from services.threat_intel import (
    check_ip_reputation,
    check_dns_reputation,
    get_vendor_advisories,
    analyze_network_threats,
    search_variot_exploits,
    get_iot_exploits_for_device,
)

router = APIRouter()


class ChatRequest(BaseModel):
    messages: list[dict]
    tools: list[dict] | None = None
    model: str = "deepseek-chat"


class ChatResponse(BaseModel):
    message: dict
    finish_reason: str
    usage: dict


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """LLM chat completion proxy."""
    try:
        result = await chat_completion(
            messages=request.messages,
            tools=request.tools,
            model=request.model,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {e}")


class CVESearchResponse(BaseModel):
    results: list[dict]


@router.get("/cve/search/{keyword}", response_model=CVESearchResponse)
async def cve_search(keyword: str):
    """Search CVEs by keyword."""
    results = await search_cve(keyword)
    return {"results": results}


@router.get("/cve/{cve_id}")
async def cve_get(cve_id: str):
    """Get CVE by ID."""
    result = await get_cve_by_id(cve_id)
    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")
    return result


# Threat Intelligence Endpoints

@router.get("/threat/ip/{ip}")
async def threat_ip_check(ip: str):
    """Check IP reputation across threat intelligence sources."""
    result = await check_ip_reputation(ip)
    return result


@router.get("/threat/dns/{dns_ip}")
async def threat_dns_check(dns_ip: str):
    """Check if a DNS server is known malicious."""
    result = await check_dns_reputation(dns_ip)
    return result


@router.get("/threat/vendor/{vendor}")
async def threat_vendor_advisories(vendor: str):
    """Get security advisories for a vendor."""
    advisories = await get_vendor_advisories(vendor)
    return {"vendor": vendor, "advisories": advisories}


@router.get("/threat/iot/{vendor}")
async def threat_iot_exploits(vendor: str, model: str = None):
    """Get IoT exploits and vulnerabilities for a device from VARIoT database."""
    result = await get_iot_exploits_for_device(vendor, model)
    return result


@router.get("/threat/exploits/{keyword}")
async def threat_search_exploits(keyword: str):
    """Search VARIoT IoT exploits database."""
    exploits = await search_variot_exploits(keyword)
    return {"keyword": keyword, "exploits": exploits}


class DeviceIdentifyRequest(BaseModel):
    ip: str
    mac: str
    open_ports: list[int] = []
    banners: dict = {}
    http_info: dict = {}


@router.post("/identify/device")
async def identify_unknown_device(request: DeviceIdentifyRequest):
    """Use LLM to identify an unknown device based on its characteristics."""
    prompt = f"""You are a network device identification expert. Identify this device based on available data.

IP: {request.ip}
MAC: {request.mac}
Open Ports: {request.open_ports}

CRITICAL RULES (follow exactly):
1. If IP ends in .1 or .254 AND has ports 53/80/443 → "Router" (high confidence)
2. Port 5000 or 5001 → "NAS Device" (medium confidence)
3. Port 8008 → "Chromecast" (high confidence)
4. Port 9000 → "Sonos Speaker" (high confidence)  
5. Port 62078 → "Apple Device" (high confidence)
6. Port 554 → "IP Camera" (high confidence)
7. Port 1883 → "IoT Device" (medium confidence)
8. Only ports 80/443 with no other distinctive features → "Unknown Device" (low confidence)

If no rules match, return "Unknown Device" (low confidence).

OUTPUT (JSON only, no explanation):
{{"device_type": "type", "vendor": "vendor_or_Unknown", "confidence": "high|medium|low", "reasoning": "1-sentence"}}

Identify now:"""
    try:
        result = await chat_completion(
            messages=[{"role": "user", "content": prompt}],
            model="deepseek-chat",
        )
        
        # Parse LLM response
        content = result["message"]["content"]
        
        # Try to extract JSON from response
        import json
        import re
        json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                return {"ip": request.ip, "mac": request.mac, "identification": parsed}
            except json.JSONDecodeError:
                pass
        
        return {"ip": request.ip, "mac": request.mac, "identification": {"raw_response": content}}
    except Exception as e:
        return {"ip": request.ip, "mac": request.mac, "error": str(e)}


class NetworkScanData(BaseModel):
    devices: list[dict]
    network: str | None = None


@router.post("/threat/analyze")
async def threat_analyze_network(scan_data: NetworkScanData):
    """Analyze network scan data for threats using threat intelligence."""
    result = await analyze_network_threats(scan_data.model_dump())
    return result
