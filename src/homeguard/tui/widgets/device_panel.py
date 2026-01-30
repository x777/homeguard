"""Device details panel widget."""

from rich.text import Text
from textual.widgets import Static
from textual.message import Message


class DevicePanel(Static):
    """Panel showing detailed device information."""
    
    class FixRequested(Message):
        """Emitted when user wants to fix device issues."""
        def __init__(self, device: dict, vulnerabilities: list):
            self.device = device
            self.vulnerabilities = vulnerabilities
            super().__init__()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.device: dict | None = None

    def show_device(self, device: dict) -> None:
        """Display device details."""
        self.device = device
        self.update(self._render_device(device))

    def clear_device(self) -> None:
        """Clear the panel."""
        self.device = None
        self.update("[dim]Select a device to view details[/dim]")

    def show_recommendations(self, recommendations: list[str]) -> None:
        """Display AI recommendations."""
        text = Text()
        text.append("🤖 AI Recommendations\n\n", style="bold cyan")
        for i, rec in enumerate(recommendations, 1):
            text.append(f"{i}. ", style="bold")
            text.append(f"{rec}\n\n")
        self.update(text)
        self.refresh()

    def _render_device(self, device: dict) -> Text:
        """Render device info as Rich Text."""
        text = Text()
        
        # Basic info
        text.append("📍 ", style="bold")
        text.append(device.get("ip", "Unknown"), style="cyan bold")
        text.append("\n\n")
        
        text.append("MAC: ", style="dim")
        text.append(f"{device.get('mac', 'Unknown')}\n")
        
        text.append("Type: ", style="dim")
        text.append(f"{device.get('device_type', 'Unknown')}\n")
        
        text.append("Vendor: ", style="dim")
        text.append(f"{device.get('vendor', 'Unknown')}\n")
        
        text.append("OS: ", style="dim")
        text.append(f"{device.get('os_guess', 'Unknown')}\n")
        
        if device.get("model"):
            text.append("Model: ", style="dim")
            text.append(f"{device['model']}\n")
        
        # Ports
        ports = device.get("open_ports", [])
        if ports:
            text.append("\n🔓 Open Ports:\n", style="bold")
            for p in ports[:8]:
                port = p.get("port", p) if isinstance(p, dict) else p
                service = p.get("service", "?") if isinstance(p, dict) else "?"
                text.append(f"  • {port}/{service}\n")
            if len(ports) > 8:
                text.append(f"  ... and {len(ports) - 8} more\n", style="dim")
        
        # Risks
        risks = device.get("risks", [])
        if risks:
            text.append("\n⚠️ Risks:\n", style="bold yellow")
            for risk in risks[:5]:
                text.append(f"  • {risk}\n", style="yellow")
        
        # Threat intel
        threat = device.get("threat_intel", {})
        advisories = threat.get("advisories", []) + threat.get("vulnerabilities", [])
        if advisories:
            text.append("\n🛡️ CVEs:\n", style="bold red")
            for adv in advisories[:5]:
                cve = adv.get("cve_id", adv.get("id", "Unknown"))
                sev = adv.get("severity", "?")
                text.append(f"  • {cve} ({sev})\n", style="red")
        
        # Deep scan findings
        deep = device.get("deep_scan", {})
        findings = deep.get("findings", [])
        if findings:
            text.append("\n🔍 Scan Findings:\n", style="bold")
            for f in findings[:5]:
                if isinstance(f, dict):
                    note = f.get("note", f.get("status", str(f)))
                else:
                    note = str(f)
                text.append(f"  • {note[:60]}\n")
        
        # Fixable vulnerabilities (NEW)
        fixable_vulns = device.get("fixable_vulnerabilities", [])
        if fixable_vulns:
            text.append("\n🔧 Fixable Issues:\n", style="bold green")
            for vuln in fixable_vulns[:3]:
                severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(vuln.get("severity"), "⚪")
                text.append(f"  {severity_icon} {vuln.get('description', 'Unknown issue')}\n", style="green")
            if len(fixable_vulns) > 3:
                text.append(f"  ... and {len(fixable_vulns) - 3} more\n", style="dim")
            text.append(f"\n  Press 'f' to fix these issues\n", style="bold green")
        
        # Fingerprint info (NEW)
        if device.get("fingerprint_match"):
            match_info = device["fingerprint_match"]
            text.append(f"\n🔍 Device Recognition:\n", style="bold blue")
            text.append(f"  Match: {match_info['type']} ({match_info['confidence']:.0%})\n", style="blue")
            text.append(f"  Seen: {match_info.get('seen_count', 1)} times\n", style="blue")
        
        return text
