"""Findings tree widget."""

from textual.widgets import Tree


class FindingsTree(Tree):
    """Tree widget for security findings grouped by risk level."""

    def __init__(self, **kwargs):
        super().__init__("Security Findings", **kwargs)

    def load_findings(self, devices: list[dict]) -> None:
        """Load findings from device list."""
        self.clear()
        self.root.remove_children()
        
        # Group by risk level
        critical = []
        high = []
        medium = []
        low = []
        
        for device in devices:
            ip = device.get("ip", "Unknown")
            
            # Check threat intel - multiple possible structures
            threat = device.get("threat_intel", {})
            
            # CVEs from advisories/vulnerabilities
            for adv in threat.get("advisories", []) + threat.get("vulnerabilities", []):
                sev = adv.get("severity", "").lower()
                cve = adv.get("cve_id", adv.get("id", "Unknown"))
                desc = adv.get("description", "")[:40]
                finding = f"{ip}: {cve} - {desc}"
                if sev == "critical":
                    critical.append(finding)
                elif sev == "high":
                    high.append(finding)
                else:
                    medium.append(finding)
            
            # Threat intel findings
            for f in threat.get("findings", []):
                if isinstance(f, str) and f:
                    medium.append(f"{ip}: {f[:50]}")
            
            # Check if marked malicious
            if threat.get("is_malicious"):
                critical.append(f"{ip}: Flagged as malicious IP!")
            
            # Check risks list
            for risk in device.get("risks", []):
                medium.append(f"{ip}: {risk}")
            
            # Check deep scan findings
            deep = device.get("deep_scan", {})
            if isinstance(deep, dict):
                for f in deep.get("findings", []):
                    if isinstance(f, dict):
                        note = f.get("note", f.get("status", ""))
                        if note:
                            if "warning" in note.lower() or "no auth" in note.lower():
                                high.append(f"{ip}: {note[:50]}")
                            else:
                                low.append(f"{ip}: {note[:50]}")
                    elif isinstance(f, str) and f:
                        low.append(f"{ip}: {f[:50]}")
            
            # Check encryption findings
            enc = device.get("encryption_check", {})
            if isinstance(enc, dict):
                for f in enc.get("findings", []):
                    if isinstance(f, str):
                        if "weak" in f.lower() or "tls 1.0" in f.lower() or "tls 1.1" in f.lower():
                            high.append(f"{ip}: {f[:50]}")
                        elif "http" in f.lower() and "https" not in f.lower():
                            medium.append(f"{ip}: {f[:50]}")
                        else:
                            low.append(f"{ip}: {f[:50]}")
            
            # Check UPnP findings
            upnp = device.get("upnp_check", {})
            if isinstance(upnp, dict):
                if upnp.get("upnp_found") or upnp.get("exposed"):
                    medium.append(f"{ip}: UPnP enabled - potential security risk")
                for f in upnp.get("findings", []):
                    if isinstance(f, str):
                        medium.append(f"{ip}: {f[:50]}")
        
        # Build tree nodes
        if critical:
            node = self.root.add(f"🔴 Critical ({len(critical)})")
            node.expand()
            for f in critical[:20]:
                node.add_leaf(f)
        
        if high:
            node = self.root.add(f"🟠 High ({len(high)})")
            node.expand()
            for f in high[:20]:
                node.add_leaf(f)
        
        if medium:
            node = self.root.add(f"🟡 Medium ({len(medium)})")
            for f in medium[:20]:
                node.add_leaf(f)
        
        if low:
            node = self.root.add(f"🟢 Low ({len(low)})")
            for f in low[:20]:
                node.add_leaf(f)
        
        if not (critical or high or medium or low):
            self.root.add_leaf("✅ No security issues found")
        
        self.root.expand()
        self.refresh()
