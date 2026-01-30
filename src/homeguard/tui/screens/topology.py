"""Network topology visualization screen."""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Tree, Static


class TopologyScreen(Screen):
    """Full-screen network topology visualization."""

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("q", "go_back", "Back"),
    ]

    CSS = """
    #topology-container { layout: horizontal; height: 100%; }
    #tree-panel { width: 50%; height: 100%; border: solid $primary; }
    #details-panel { width: 50%; height: 100%; border: solid $secondary; padding: 1; }
    #device-details { height: 1fr; }
    #risk-summary { height: auto; border-top: solid $primary; padding: 1; }
    """

    def __init__(self, devices: list[dict] | None = None, **kwargs):
        super().__init__(**kwargs)
        self.devices = devices or []
        self.device_map: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="topology-container"):
            yield Tree("🌐 Network Topology", id="tree-panel")
            with Vertical(id="details-panel"):
                yield Static("Select a device to view details", id="device-details")
                yield Static(self._build_risk_summary(), id="risk-summary")
        yield Footer()

    def on_mount(self) -> None:
        """Build the topology tree."""
        tree = self.query_one(Tree)
        tree.root.expand()

        if not self.devices:
            tree.root.add_leaf("No devices")
            return

        # Find router
        router = None
        others = []
        for d in self.devices:
            dtype = d.get("device_type", "").lower()
            ip = d.get("ip", "")
            if "router" in dtype or "gateway" in dtype or ip.endswith(".1"):
                router = d
            else:
                others.append(d)

        # Add router node
        if router:
            r_label = self._format_label(router)
            router_node = tree.root.add(r_label, data=router)
            router_node.expand()
            self.device_map[r_label] = router

            for device in others:
                label = self._format_label(device)
                router_node.add_leaf(label, data=device)
                self.device_map[label] = device
        else:
            for device in self.devices:
                label = self._format_label(device)
                tree.root.add_leaf(label, data=device)
                self.device_map[label] = device

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Show device details when selected."""
        if event.node.data:
            details = self.query_one("#device-details", Static)
            details.update(self._build_details(event.node.data))

    def _format_label(self, device: dict) -> str:
        """Format device label."""
        icon = self._get_icon(device)
        ip = device.get("ip", "?")
        color = self._get_color(device)
        return f"[{color}]{icon}[/] {ip}"

    def _build_details(self, device: dict) -> str:
        """Build device details panel."""
        lines = []
        color = self._get_color(device)
        icon = self._get_icon(device)
        
        lines.append(f"[bold]{icon} {device.get('ip', 'Unknown')}[/bold]")
        lines.append("")
        lines.append(f"[dim]Type:[/dim]    {device.get('device_type', 'Unknown')}")
        lines.append(f"[dim]Vendor:[/dim]  {device.get('vendor', 'Unknown')}")
        lines.append(f"[dim]MAC:[/dim]     {device.get('mac', 'Unknown')}")
        lines.append(f"[dim]Risk:[/dim]    [{color}]●[/] {self._get_risk_label(device)}")
        
        # Ports
        ports = device.get("open_ports", [])
        if ports:
            port_str = ", ".join(str(p.get("port", p) if isinstance(p, dict) else p) for p in ports[:8])
            if len(ports) > 8:
                port_str += f" (+{len(ports) - 8})"
            lines.append(f"[dim]Ports:[/dim]   {port_str}")
        
        # Threats
        threat = device.get("threat_intel", {})
        cves = threat.get("advisories", []) + threat.get("vulnerabilities", [])
        if cves:
            lines.append("")
            lines.append("[bold red]⚠ Vulnerabilities:[/bold red]")
            for cve in cves[:5]:
                cve_id = cve.get("cve_id", cve.get("id", "?"))
                sev = cve.get("severity", "?")
                lines.append(f"  • {cve_id} ({sev})")
        
        # Deep scan findings
        deep = device.get("deep_scan", {})
        findings = deep.get("findings", [])
        if findings:
            lines.append("")
            lines.append("[bold yellow]🔍 Findings:[/bold yellow]")
            for f in findings[:5]:
                note = f.get("note", str(f)) if isinstance(f, dict) else str(f)
                lines.append(f"  • {note[:50]}")
        
        return "\n".join(lines)

    def _build_risk_summary(self) -> str:
        """Build risk distribution summary."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for d in self.devices:
            risk = self._get_risk_label(d).lower()
            if "critical" in risk:
                counts["critical"] += 1
            elif "high" in risk:
                counts["high"] += 1
            elif "medium" in risk:
                counts["medium"] += 1
            else:
                counts["low"] += 1
        
        total = len(self.devices)
        return (
            f"[bold]Risk Summary[/bold] ({total} devices)\n"
            f"[red]● Critical: {counts['critical']}[/]  "
            f"[#ff8800]● High: {counts['high']}[/]  "
            f"[yellow]● Medium: {counts['medium']}[/]  "
            f"[green]● Low: {counts['low']}[/]"
        )

    def _get_risk_label(self, device: dict) -> str:
        """Get risk level label."""
        threat = device.get("threat_intel", {})
        if threat.get("is_malicious"):
            return "CRITICAL"
        
        advisories = threat.get("advisories", []) + threat.get("vulnerabilities", [])
        for adv in advisories:
            sev = adv.get("severity", "").lower()
            if sev == "critical":
                return "CRITICAL"
            if sev == "high":
                return "HIGH"
        
        if device.get("risks") or device.get("deep_scan", {}).get("findings"):
            return "MEDIUM"
        
        return "LOW"

    def _get_color(self, device: dict) -> str:
        """Get color based on risk."""
        risk = self._get_risk_label(device)
        return {"CRITICAL": "red", "HIGH": "#ff8800", "MEDIUM": "yellow"}.get(risk, "green")

    def _get_icon(self, device: dict) -> str:
        """Get icon for device type."""
        dtype = device.get("device_type", "").lower()
        icons = {
            "router": "🌐", "gateway": "🌐", "phone": "📱", "mobile": "📱",
            "computer": "🖥", "pc": "🖥", "desktop": "🖥", "laptop": "💻",
            "tv": "📺", "camera": "📷", "iot": "🔌", "smart": "🔌",
            "nas": "💾", "storage": "💾", "printer": "🖨",
        }
        for key, icon in icons.items():
            if key in dtype:
                return icon
        return "📟"

    def action_go_back(self) -> None:
        """Return to main screen."""
        self.app.pop_screen()
