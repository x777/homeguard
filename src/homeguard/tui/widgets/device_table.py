"""Device table widget."""

from textual.message import Message
from textual.widgets import DataTable

# Ports commonly associated with security risks
RISKY_PORTS = {21, 23, 25, 110, 143, 445, 3389, 5900}  # FTP, Telnet, SMTP, POP3, IMAP, SMB, RDP, VNC


class DeviceTable(DataTable):
    """DataTable for displaying discovered devices."""

    class DeviceSelected(Message):
        """Emitted when a device row is selected."""
        def __init__(self, device: dict):
            self.device = device
            super().__init__()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.devices: dict[str, dict] = {}

    def on_mount(self) -> None:
        """Set up columns - all auto-width to fit content."""
        self.add_column("IP")
        self.add_column("Type")
        self.add_column("Vendor")
        self.add_column("Fingerprint")
        self.add_column("Risk")
        self.add_column("Ports")
        self.cursor_type = "row"

    def add_device(self, device: dict) -> None:
        """Add a device to the table."""
        row_key = self.add_row(
            device.get("ip", "Unknown"),
            device.get("device_type", "Unknown"),
            device.get("vendor", "Unknown"),
            self._get_fingerprint_display(device),
            self._get_risk_level(device),
            self._format_ports(device.get("open_ports", [])),
        )
        self.devices[row_key] = device

    def clear_devices(self) -> None:
        """Clear all devices from table."""
        self.clear()
        self.devices.clear()

    def load_devices(self, devices: list[dict]) -> None:
        """Load multiple devices."""
        self.clear_devices()
        for device in devices:
            self.add_device(device)

    def _get_risk_level(self, device: dict) -> str:
        """Determine risk level for device."""
        threat = device.get("threat_intel", {})
        
        # Check CVE advisories
        advisories = threat.get("advisories", []) + threat.get("vulnerabilities", [])
        for adv in advisories:
            sev = adv.get("severity", "").lower()
            if sev == "critical":
                return "🔴 CRITICAL"
            if sev == "high":
                return "🟠 HIGH"
        
        # Check IP reputation
        if threat.get("is_malicious"):
            return "🔴 CRITICAL"
        if threat.get("risk_score", 0) > 50:
            return "🟠 HIGH"
        
        # Check deep scan findings for critical/high severity
        deep = device.get("deep_scan", {})
        for finding in deep.get("findings", []):
            if isinstance(finding, dict):
                sev = finding.get("severity", "").lower()
                if sev == "critical":
                    return "🔴 CRITICAL"
                if sev == "high":
                    return "🟠 HIGH"
                # Check for warning status (like "WARNING - No authentication")
                status = finding.get("status", "")
                if "WARNING" in status.upper() or "NO AUTH" in status.upper():
                    return "🟠 HIGH"
        
        # Check encryption findings
        enc = device.get("encryption_check", {})
        if enc.get("risk_level") == "high":
            return "🟠 HIGH"
        
        # Check for risky open ports on routers/gateways
        device_type = device.get("device_type", "").lower()
        if "router" in device_type or "gateway" in device_type:
            open_ports = device.get("open_ports", [])
            port_nums = {self._get_port_num(p) for p in open_ports} - {None}
            # Router with admin ports exposed is high risk
            if port_nums & {80, 443, 8080, 8443}:
                return "🟠 HIGH"
        
        # Check risks array
        if device.get("risks"):
            return "🟡 MEDIUM"
        
        # Check for any findings (medium risk)
        upnp = device.get("upnp_check", {})
        if deep.get("findings") or enc.get("findings") or upnp.get("upnp_found"):
            return "🟡 MEDIUM"
        
        # Check open ports
        open_ports = device.get("open_ports", [])
        port_nums = {self._get_port_num(p) for p in open_ports} - {None}
        if port_nums & RISKY_PORTS or len(open_ports) > 5:
            return "🟡 MEDIUM"
        
        return "🟢 LOW"

    def _get_fingerprint_display(self, device: dict) -> str:
        """Format fingerprint for display."""
        fp_match = device.get("fingerprint_match")
        if fp_match:
            match_type = fp_match.get("type", "new")
            seen = fp_match.get("seen_count", 1)
            if match_type == "exact":
                return f"✓ Seen {seen}x"
            elif match_type == "similar":
                return f"≈ Similar"
            return "● New"
        
        fp_id = device.get("fingerprint_id", "")
        return fp_id[:8] if fp_id else "-"

    def _get_port_num(self, port) -> int | None:
        """Extract port number from port entry."""
        if isinstance(port, dict):
            return port.get("port")
        return port if isinstance(port, int) else None

    def _format_ports(self, ports: list) -> str:
        """Format ports for display."""
        if not ports:
            return "-"
        port_nums = [str(self._get_port_num(p) or "?") for p in ports[:5]]
        result = ", ".join(port_nums)
        if len(ports) > 5:
            result += f" (+{len(ports) - 5})"
        return result

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        if event.row_key in self.devices:
            self.post_message(self.DeviceSelected(self.devices[event.row_key]))

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """Sort by clicked column header."""
        self.sort(event.column_key)
