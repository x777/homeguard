# Device Identification Improvements

## Current Issues

### 1. Missing Data
- **MAC Address**: Not captured (requires sudo/root)
- **Open Ports**: Empty results (quick scan too fast)
- **Hostname**: Not resolved properly
- **Vendor**: Limited database

### 2. Identification Logic Gaps
- Only checks ~10 vendors
- No mDNS/Bonjour discovery
- No DHCP fingerprinting
- No HTTP User-Agent analysis
- No service banner analysis

## Proposed Solutions

### Phase 1: Improve Data Collection (Quick Wins)

#### 1.1 Better Hostname Resolution
```python
def get_hostname_enhanced(ip: str) -> str:
    """Enhanced hostname resolution with multiple methods."""
    # Try standard DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except:
        pass
    
    # Try mDNS (Bonjour) - common on Apple/IoT
    try:
        import subprocess
        result = subprocess.run(
            ["dns-sd", "-G", "v4", ip],
            capture_output=True, timeout=2, text=True
        )
        # Parse output for hostname
        if result.returncode == 0:
            # Extract hostname from dns-sd output
            pass
    except:
        pass
    
    return None
```

#### 1.2 HTTP-Based Identification
```python
def identify_from_http(ip: str, port: int = 80) -> dict:
    """Identify device from HTTP headers and content."""
    info = {}
    
    try:
        req = urllib.request.Request(f"http://{ip}:{port}/")
        req.add_header("User-Agent", "HomeGuard/1.0")
        
        with urllib.request.urlopen(req, timeout=3) as resp:
            # Server header
            server = resp.headers.get("Server", "")
            if server:
                info["server"] = server
                # Parse server for device hints
                if "synology" in server.lower():
                    info["device_type"] = "Synology NAS"
                elif "qnap" in server.lower():
                    info["device_type"] = "QNAP NAS"
                elif "apache" in server.lower():
                    info["device_type"] = "Web Server"
            
            # Page title
            html = resp.read(8192).decode(errors="ignore")
            title_match = re.search(r"<title>([^<]+)</title>", html, re.I)
            if title_match:
                title = title_match.group(1).strip()
                info["title"] = title
                
                # Device hints from title
                if "router" in title.lower():
                    info["device_type"] = "Router"
                elif "camera" in title.lower():
                    info["device_type"] = "IP Camera"
                elif "printer" in title.lower():
                    info["device_type"] = "Printer"
                elif "nas" in title.lower():
                    info["device_type"] = "NAS"
    except:
        pass
    
    return info
```

#### 1.3 Service Banner Analysis
```python
def analyze_banner(banner: str) -> dict:
    """Extract device info from service banners."""
    info = {}
    
    # SSH banners reveal OS/device
    if "SSH" in banner:
        if "Dropbear" in banner:
            info["device_type"] = "Embedded Device/Router"
        elif "OpenSSH" in banner:
            if "Ubuntu" in banner:
                info["os"] = "Ubuntu Linux"
            elif "Debian" in banner:
                info["os"] = "Debian Linux"
        elif "MikroTik" in banner:
            info["device_type"] = "MikroTik Router"
    
    # FTP banners
    if "FTP" in banner:
        if "Synology" in banner:
            info["device_type"] = "Synology NAS"
        elif "QNAP" in banner:
            info["device_type"] = "QNAP NAS"
    
    return info
```

### Phase 2: Enhanced Port-Based Detection

#### 2.1 Expand Port Signatures
```python
DEVICE_PORT_SIGNATURES = {
    "Apple TV": [3689, 7000, 49152],
    "Sonos": [1400, 1443, 3400, 3401, 3500],
    "Philips Hue": [80, 443, 1900],  # + specific HTTP response
    "Nest": [443, 11095],
    "Ring": [443, 8883],
    "Alexa/Echo": [4070, 55442, 55443],
    "Google Home": [8008, 8009, 8443, 9000],
    "Roku": [8060, 8443],
    "Fire TV": [8008, 8009],
    "Smart Bulb": [80, 9999],
    "Raspberry Pi": [22, 80],  # + SSH banner check
}
```

#### 2.2 Confidence Scoring
```python
def calculate_confidence(indicators: dict) -> tuple[str, float]:
    """Calculate device type confidence score."""
    scores = {}
    
    # Port match: +30 points per matching port
    if "port_matches" in indicators:
        for device_type, matched_ports in indicators["port_matches"].items():
            scores[device_type] = len(matched_ports) * 30
    
    # Vendor match: +50 points
    if "vendor" in indicators:
        vendor = indicators["vendor"]
        if vendor in ["Apple", "Sonos", "Roku"]:
            scores[vendor] = scores.get(vendor, 0) + 50
    
    # HTTP title match: +40 points
    if "http_title_match" in indicators:
        device_type = indicators["http_title_match"]
        scores[device_type] = scores.get(device_type, 0) + 40
    
    # Banner match: +60 points (high confidence)
    if "banner_match" in indicators:
        device_type = indicators["banner_match"]
        scores[device_type] = scores.get(device_type, 0) + 60
    
    # Get highest score
    if scores:
        best_match = max(scores.items(), key=lambda x: x[1])
        device_type, score = best_match
        confidence = min(score / 100, 1.0)  # Normalize to 0-1
        
        if confidence >= 0.8:
            return device_type, "high"
        elif confidence >= 0.5:
            return device_type, "medium"
        else:
            return device_type, "low"
    
    return "Unknown", "low"
```

### Phase 3: mDNS/Bonjour Discovery

```python
def discover_mdns_devices() -> list:
    """Discover devices via mDNS/Bonjour."""
    devices = []
    
    try:
        from zeroconf import Zeroconf, ServiceBrowser
        
        class DeviceListener:
            def __init__(self):
                self.devices = []
            
            def add_service(self, zeroconf, service_type, name):
                info = zeroconf.get_service_info(service_type, name)
                if info:
                    self.devices.append({
                        "name": name,
                        "ip": socket.inet_ntoa(info.addresses[0]),
                        "port": info.port,
                        "type": service_type,
                        "properties": info.properties
                    })
        
        zc = Zeroconf()
        listener = DeviceListener()
        
        # Common mDNS service types
        services = [
            "_http._tcp.local.",
            "_airplay._tcp.local.",
            "_homekit._tcp.local.",
            "_googlecast._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_printer._tcp.local.",
        ]
        
        browsers = [ServiceBrowser(zc, service, listener) for service in services]
        time.sleep(3)  # Wait for discovery
        
        zc.close()
        devices = listener.devices
        
    except ImportError:
        # zeroconf not installed
        pass
    except Exception as e:
        pass
    
    return devices
```

## Implementation Priority

### High Priority (Implement Now)
1. ✅ HTTP-based identification (no dependencies)
2. ✅ Service banner analysis (already have banners)
3. ✅ Expanded port signatures
4. ✅ Confidence scoring system

### Medium Priority
5. Enhanced hostname resolution
6. mDNS/Bonjour discovery (requires zeroconf package)

### Low Priority
7. DHCP fingerprinting (complex, requires packet capture)
8. Machine learning classification (overkill for now)

## Quick Implementation

**File to modify**: `src/homeguard/agent/tools/network.py`

**Changes**:
1. Add HTTP identification function
2. Expand port signature database
3. Add confidence scoring
4. Integrate banner analysis from deep_scan

**Expected Improvement**:
- Unknown devices: 60% → 20%
- Identification confidence: +40%
- No new dependencies required
