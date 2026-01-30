"""Main dashboard screen."""

from dataclasses import asdict
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, ListView, ListItem, Label
from textual.worker import Worker, WorkerState

from homeguard.agent.report import list_reports, load_report
from homeguard.agent.tools import execute_tool
from homeguard.tui.widgets import DeviceTable, DevicePanel, FindingsTree, ChatWindow, FixModal
from homeguard.tui.chat_client import ChatClient


class MainScreen(Screen):
    """Main dashboard screen with device table and history."""

    BINDINGS = [
        ("s", "start_scan", "Quick Scan"),
        ("a", "ai_scan", "AI Scan"),
        ("t", "topology", "Topology"),
        ("m", "monitoring", "Monitor"),
        ("f", "fix_issues", "Fix Issues"),
        ("r", "refresh", "Refresh"),
        ("c", "toggle_chat", "Chat"),
        ("g", "settings", "Settings"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.chat_client = ChatClient()
        self.selected_device = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-container"):
            # History sidebar
            with Vertical(id="history-panel"):
                yield Static("📋 History", classes="title")
                yield ListView(id="history-list")
            
            # Main content
            with Vertical(id="content-panel"):
                yield DeviceTable(id="device-table")
                with Horizontal(id="details-row"):
                    yield DevicePanel(id="device-panel")
                    yield FindingsTree(id="findings-tree")
        yield ChatWindow(id="chat-window")
        yield Footer()

    def on_mount(self) -> None:
        """Load history on mount."""
        self._load_history()
        # Initialize panel
        try:
            panel = self.query_one(DevicePanel)
            panel.update("Select a device or load a report from history")
        except Exception:
            pass

    def _load_history(self) -> None:
        """Load scan history into sidebar."""
        history_list = self.query_one("#history-list", ListView)
        
        # Remove all children manually to avoid async issues
        for child in list(history_list.children):
            child.remove()
        
        reports = list_reports()
        for i, report in enumerate(reports[:20]):
            scan_id = report["scan_id"]
            time_str = report["scan_time"].split()[0] if " " in report["scan_time"] else scan_id
            devices = report["total_devices"]
            risk = report.get("overall_risk", "low")
            scan_mode = report.get("scan_mode", "quick")
            
            # Icons for scan types
            scan_icon = "🤖" if scan_mode == "full" else "⚡"
            risk_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(risk, "🟢")
            
            label = f"{scan_icon} {risk_icon} {time_str}\n   {devices} devices"
            
            # Use unique timestamp-based ID
            import time
            unique_id = f"h{int(time.time()*1000)}{i}"
            item = ListItem(Label(label), id=unique_id)
            item.scan_id = scan_id
            history_list.append(item)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle history item selection."""
        # Prevent report switching when chat is open
        chat = self.query_one(ChatWindow)
        if chat.is_visible:
            self.notify("Close chat window first to switch reports", severity="warning")
            return
            
        item = event.item
        if hasattr(item, "scan_id"):
            self._load_report(item.scan_id)

    def _load_report(self, scan_id: str) -> None:
        """Load a historical report."""
        import logging
        logger = logging.getLogger("homeguard.tui")
        
        report = load_report(scan_id)
        if not report:
            self.notify(f"Could not load report {scan_id}", severity="error")
            return
        
        # Convert DeviceReport objects to dicts
        devices = [asdict(d) for d in report.devices]
        logger.info(f"_load_report: {len(devices)} devices from report {scan_id}")
        
        # Update device table
        table = self.query_one(DeviceTable)
        table.load_devices(devices)
        logger.info(f"_load_report: table.devices now has {len(table.devices)} items")
        
        # Update findings tree - query by type since it's nested in TabPane
        try:
            tree = self.query_one(FindingsTree)
            tree.load_findings(devices)
        except Exception as e:
            self.notify(f"Findings error: {e}", severity="warning")
        
        # Show recommendations in device panel if available
        try:
            panel = self.query_one(DevicePanel)
            if report.overall_recommendations:
                panel.show_recommendations(report.overall_recommendations)
            else:
                panel.update(f"Loaded {len(devices)} devices. Click a row to view details.")
        except Exception as e:
            self.notify(f"Panel error: {e}", severity="warning")
        
        # Update chat context
        try:
            chat = self.query_one(ChatWindow)
            context = f"Report {scan_id}: {len(devices)} devices, {report.overall_risk} risk"
            chat.set_report_context(context, scan_id)
            # Reset chat client conversation for new report
            self.chat_client.reset_conversation()
        except Exception:
            pass
        
        self.notify(f"Loaded: {len(devices)} devices", severity="information")

    def on_device_table_device_selected(self, event: DeviceTable.DeviceSelected) -> None:
        """Handle device selection."""
        self.selected_device = event.device
        panel = self.query_one(DevicePanel)
        panel.show_device(event.device)

    def action_fix_issues(self) -> None:
        """Fix issues for selected device."""
        if not self.selected_device:
            self.notify("Select a device first", severity="warning")
            return
        
        vulns = self.selected_device.get("fixable_vulnerabilities", [])
        if not vulns:
            self.notify("No fixable issues for this device", severity="information")
            return
        
        self.push_screen(FixModal(self.selected_device, vulns), self._handle_fix_confirmed)
    
    def _handle_fix_confirmed(self, result) -> None:
        """Handle fix confirmation from modal."""
        if result:
            self.run_worker(self._execute_fixes, result.device, result.vulnerabilities, thread=True)
    
    def _execute_fixes(self, device, vulnerabilities):
        """Execute fixes in background."""
        ip = device.get("ip", "Unknown")
        self.app.call_from_thread(self.notify, f"Fixing {len(vulnerabilities)} issues on {ip}...")
        
        results = []
        for vuln in vulnerabilities:
            # Execute fix
            result = execute_tool("auto_fix_vulnerability", {
                "ip": ip,
                "vuln_id": vuln.get("vuln_id"),
                "device_data": device
            })
            results.append((vuln, result))
        
        # Show results
        success_count = sum(1 for _, r in results if r and r.success)
        self.app.call_from_thread(
            self.notify,
            f"✅ Fixed {success_count}/{len(vulnerabilities)} issues on {ip}",
            severity="success" if success_count == len(vulnerabilities) else "warning"
        )

    def action_start_scan(self) -> None:
        """Start a quick scan (no AI)."""
        from homeguard.tui.screens.scan import ScanScreen
        self.app.push_screen(ScanScreen(full_scan=False))

    def action_ai_scan(self) -> None:
        """Run full AI scan with deep scans, threat intel, and recommendations."""
        from homeguard.tui.screens.scan import ScanScreen
        self.app.push_screen(ScanScreen(full_scan=True))

    def action_refresh(self) -> None:
        """Refresh history list."""
        self._load_history()

    def action_monitoring(self) -> None:
        """Show monitoring screen."""
        from homeguard.tui.screens.monitoring import MonitoringScreen
        self.app.push_screen(MonitoringScreen(monitor=self.app.monitor))

    def action_topology(self) -> None:
        """Show network topology view."""
        import logging
        logger = logging.getLogger("homeguard.tui")
        from homeguard.tui.screens.topology import TopologyScreen
        table = self.query_one(DeviceTable)
        devices = list(table.devices.values())
        logger.info(f"Topology: table.devices has {len(table.devices)} items, devices list has {len(devices)}")
        if not devices:
            self.notify("Load a report first (click history item)", severity="warning")
            return
        self.app.push_screen(TopologyScreen(devices=devices))

    def action_quit(self) -> None:
        """Quit the app."""
        self.app.exit()

    def action_settings(self) -> None:
        """Open LLM settings screen."""
        from homeguard.tui.screens.llm_settings import LLMSettingsScreen
        
        def on_settings_closed(result=None):
            # Reload chat client with new config
            self.chat_client = ChatClient()
            
        self.app.push_screen(LLMSettingsScreen(), on_settings_closed)

    def action_toggle_chat(self) -> None:
        """Toggle chat window visibility."""
        chat = self.query_one(ChatWindow)
        chat.toggle_visibility()

    def on_chat_window_chat_submit(self, event: ChatWindow.ChatSubmit) -> None:
        """Handle chat message submission."""
        chat = self.query_one(ChatWindow)
        chat.add_loading_indicator()
        
        # Run async chat in worker
        self.run_worker(
            self._send_chat_message(event.message, chat.report_context),
            exclusive=False
        )
    
    async def _send_chat_message(self, message: str, context: str) -> None:
        """Send message to LLM backend."""
        chat = self.query_one(ChatWindow)
        response = await self.chat_client.send_message(message, context)
        chat.remove_loading_indicator()
        chat.add_assistant_message(response)

    def load_scan_result(self, devices: list[dict]) -> None:
        """Load scan results (called after scan completes)."""
        table = self.query_one(DeviceTable)
        table.load_devices(devices)
        
        tree = self.query_one(FindingsTree)
        tree.load_findings(devices)
        
        # Update chat context
        try:
            chat = self.query_one(ChatWindow)
            context = f"New scan: {len(devices)} devices found"
            chat.set_report_context(context, "new_scan")
            # Reset chat client conversation for new scan
            self.chat_client.reset_conversation()
        except Exception:
            pass
        
        self._load_history()  # Refresh history
