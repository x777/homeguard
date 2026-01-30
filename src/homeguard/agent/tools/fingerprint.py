"""Device fingerprinting for unique device identification."""

import hashlib
import json
from typing import Dict, Any, Optional
from pathlib import Path


class DeviceFingerprinter:
    """Creates and manages device fingerprints for identification."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".homeguard" / "fingerprints"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.fingerprint_db = self._load_fingerprint_db()
    
    def create_fingerprint(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create unique fingerprint for device."""
        # Core identifying features
        mac = device_data.get("mac", "Unknown")
        ports = sorted([p.get("port", 0) for p in device_data.get("open_ports", [])])
        
        # HTTP signature
        http_info = device_data.get("http_info", {})
        http_sig = f"{http_info.get('server', '')}{http_info.get('title', '')}"
        
        # Banner signatures
        banners = device_data.get("banners", {})
        banner_sig = "".join(sorted(banners.values())) if banners else ""
        
        # Deep scan signatures
        deep_scan = device_data.get("deep_scan", {})
        vendor_hints = []
        if deep_scan.get("http_info", {}).get("vendor"):
            vendor_hints.append(deep_scan["http_info"]["vendor"])
        
        # Create composite signature
        signature_data = {
            "mac_address": mac,  # Full MAC for uniqueness
            "mac_oui": mac[:8] if len(mac) >= 8 else mac,  # OUI for vendor matching
            "port_signature": ports,
            "http_hash": hashlib.md5(http_sig.encode()).hexdigest()[:8],
            "banner_hash": hashlib.md5(banner_sig.encode()).hexdigest()[:8],
            "vendor_hints": vendor_hints,
            "os_guess": device_data.get("os_guess", "Unknown"),
        }
        
        # Generate unique fingerprint ID
        fingerprint_str = json.dumps(signature_data, sort_keys=True)
        fingerprint_id = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
        
        return {
            "fingerprint_id": fingerprint_id,
            "signature": signature_data,
            "confidence": self._calculate_confidence(signature_data),
            "device_class": self._classify_device(signature_data),
        }
    
    def match_device(self, device_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match device against known fingerprints."""
        current_fp = self.create_fingerprint(device_data)
        
        # Exact match
        if current_fp["fingerprint_id"] in self.fingerprint_db:
            stored = self.fingerprint_db[current_fp["fingerprint_id"]]
            return {
                "match_type": "exact",
                "confidence": 1.0,
                "stored_info": stored,
                "fingerprint": current_fp
            }
        
        # Fuzzy match
        best_match = self._fuzzy_match(current_fp)
        if best_match and best_match["similarity"] > 0.7:
            return {
                "match_type": "fuzzy",
                "confidence": best_match["similarity"],
                "stored_info": best_match["stored_fp"],
                "fingerprint": current_fp
            }
        
        return None
    
    def store_fingerprint(self, device_data: Dict[str, Any], user_labels: Dict[str, str] = None) -> str:
        """Store device fingerprint with optional user labels."""
        fingerprint = self.create_fingerprint(device_data)
        fp_id = fingerprint["fingerprint_id"]
        
        # Store with metadata
        self.fingerprint_db[fp_id] = {
            "fingerprint": fingerprint,
            "device_info": {
                "ip": device_data.get("ip"),
                "device_type": device_data.get("device_type", "Unknown"),
                "vendor": device_data.get("vendor", "Unknown"),
                "model": device_data.get("model", ""),
            },
            "user_labels": user_labels or {},
            "first_seen": device_data.get("scan_time", "unknown"),
            "last_seen": device_data.get("scan_time", "unknown"),
            "seen_count": 1,
        }
        
        self._save_fingerprint_db()
        return fp_id
    
    def update_fingerprint(self, fp_id: str, device_data: Dict[str, Any]) -> None:
        """Update existing fingerprint with new scan data."""
        if fp_id in self.fingerprint_db:
            stored = self.fingerprint_db[fp_id]
            stored["last_seen"] = device_data.get("scan_time", "unknown")
            stored["seen_count"] += 1
            
            # Update device info if more specific
            if device_data.get("model") and not stored["device_info"].get("model"):
                stored["device_info"]["model"] = device_data["model"]
            
            self._save_fingerprint_db()
    
    def _calculate_confidence(self, signature: Dict[str, Any]) -> float:
        """Calculate confidence score for fingerprint."""
        score = 0.0
        
        # MAC OUI adds high confidence
        if signature["mac_oui"] != "Unknown" and len(signature["mac_oui"]) >= 8:
            score += 0.4
        
        # Port signature adds medium confidence
        if signature["port_signature"]:
            score += 0.3
        
        # HTTP signature adds medium confidence
        if signature["http_hash"] != hashlib.md5(b"").hexdigest()[:8]:
            score += 0.2
        
        # Banner signature adds low confidence
        if signature["banner_hash"] != hashlib.md5(b"").hexdigest()[:8]:
            score += 0.1
        
        return min(score, 1.0)
    
    def _classify_device(self, signature: Dict[str, Any]) -> str:
        """Classify device based on signature patterns."""
        ports = set(signature["port_signature"])
        
        # Router/Gateway patterns
        if ports & {53, 67, 80, 443} and len(ports) >= 3:
            return "router"
        
        # IoT device patterns
        if ports & {1883, 8883, 5683}:  # MQTT, CoAP
            return "iot"
        
        # Media device patterns
        if ports & {8008, 8009, 9000}:  # Chromecast, Sonos
            return "media"
        
        # Storage device patterns
        if ports & {445, 139, 2049, 5000}:  # SMB, NFS, Synology
            return "storage"
        
        # Camera patterns
        if 554 in ports:  # RTSP
            return "camera"
        
        return "unknown"
    
    def _fuzzy_match(self, fingerprint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Find fuzzy matches in fingerprint database."""
        best_match = None
        best_similarity = 0.0
        
        current_sig = fingerprint["signature"]
        
        for fp_id, stored_data in self.fingerprint_db.items():
            stored_sig = stored_data["fingerprint"]["signature"]
            similarity = self._calculate_similarity(current_sig, stored_sig)
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = {
                    "fingerprint_id": fp_id,
                    "similarity": similarity,
                    "stored_fp": stored_data
                }
        
        return best_match
    
    def _calculate_similarity(self, sig1: Dict[str, Any], sig2: Dict[str, Any]) -> float:
        """Calculate similarity between two signatures."""
        score = 0.0
        
        # MAC OUI match (high weight)
        if sig1["mac_oui"] == sig2["mac_oui"] and sig1["mac_oui"] != "Unknown":
            score += 0.5
        
        # Port signature similarity (medium weight)
        ports1 = set(sig1["port_signature"])
        ports2 = set(sig2["port_signature"])
        if ports1 and ports2:
            port_similarity = len(ports1 & ports2) / len(ports1 | ports2)
            score += port_similarity * 0.3
        
        # HTTP hash match (medium weight)
        if sig1["http_hash"] == sig2["http_hash"] and sig1["http_hash"] != hashlib.md5(b"").hexdigest()[:8]:
            score += 0.2
        
        return score
    
    def _load_fingerprint_db(self) -> Dict[str, Any]:
        """Load fingerprint database from cache."""
        db_file = self.cache_dir / "fingerprints.json"
        if db_file.exists():
            try:
                with open(db_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_fingerprint_db(self) -> None:
        """Save fingerprint database to cache."""
        db_file = self.cache_dir / "fingerprints.json"
        try:
            with open(db_file, 'w') as f:
                json.dump(self.fingerprint_db, f, indent=2)
        except Exception:
            pass
    
    def get_device_history(self, fp_id: str) -> Optional[Dict[str, Any]]:
        """Get historical data for a fingerprint."""
        return self.fingerprint_db.get(fp_id)
    
    def list_known_devices(self) -> Dict[str, Dict[str, Any]]:
        """List all known device fingerprints."""
        return {
            fp_id: {
                "device_type": data["device_info"]["device_type"],
                "vendor": data["device_info"]["vendor"],
                "model": data["device_info"]["model"],
                "seen_count": data["seen_count"],
                "last_seen": data["last_seen"],
                "confidence": data["fingerprint"]["confidence"]
            }
            for fp_id, data in self.fingerprint_db.items()
        }
