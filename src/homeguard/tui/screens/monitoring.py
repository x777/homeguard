"""Monitoring screen showing alerts and status."""

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button, ListView, ListItem, Label
from textual.worker import Worker

from homeguard.monitor.scheduler import NetworkMonitor


class MonitoringScreen(Screen):
    """Monitoring dashboard with alerts."""
    
    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("r", "run_now", "Run Now"),
        ("c", "clear_alerts", "Clear"),
        ("s", "settings", "Settings"),
    ]
    
    def __init__(self, monitor: NetworkMonitor, **kwargs):
        super().__init__(**kwargs)
        self.monitor = monitor
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="monitor-container"):
            yield Static("📊 Network Monitoring", classes="title")
            
            # Status panel
            with Vertical(id="status-panel"):
                status = "● Active" if self.monitor.settings.get("enabled") else "○ Inactive"
                interval = self.monitor.settings.get("interval_hours", 6)
                yield Static(f"Status: {status}", id="monitor-status")
                yield Static(f"Scan Interval: Every {interval} hours", id="monitor-interval")
            
            # Alerts list
            yield Static("🔔 Recent Alerts", classes="section-title")
            yield ListView(id="alerts-list")
            
            # Actions
            with Horizontal(classes="button-row"):
                yield Button("Run Scan Now", variant="primary", id="run-btn")
                yield Button("Clear Alerts", id="clear-btn")
                yield Button("Settings", id="settings-btn")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Load alerts on mount."""
        self._update_status()
        self._load_alerts()
    
    def on_screen_resume(self) -> None:
        """Refresh when returning to this screen."""
        self._update_status()
        self._load_alerts()
    
    def _update_status(self) -> None:
        """Update status display."""
        # Reload settings from disk to get latest values
        from homeguard.monitor.settings import MonitorSettings
        self.monitor.settings = MonitorSettings()
        
        enabled = self.monitor.settings.get("enabled")
        interval = self.monitor.settings.get("interval_hours", 6)
        
        status_text = f"Status: {'● Active' if enabled else '○ Inactive (Enable in Settings)'}"
        interval_text = f"Scan Interval: Every {interval} hours" if enabled else "Scan Interval: Not configured"
        
        self.query_one("#monitor-status", Static).update(status_text)
        self.query_one("#monitor-interval", Static).update(interval_text)
    
    def _load_alerts(self) -> None:
        """Load alerts into list."""
        alerts_list = self.query_one("#alerts-list", ListView)
        
        # Clear existing
        for child in list(alerts_list.children):
            child.remove()
        
        alerts = self.monitor.get_alerts(limit=20)
        
        if not alerts:
            if not self.monitor.settings.get("enabled"):
                msg = "⚠️ Monitoring is disabled. Press 's' to enable in Settings."
            else:
                msg = "No alerts yet. Monitoring is active and will scan automatically."
            alerts_list.mount(ListItem(Label(msg)))
            return
        
        for alert in alerts:
            severity_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(alert["severity"], "⚪")
            
            title = f"{severity_icon} {alert['title']}"
            desc = alert['description']
            time = alert['timestamp'].split('T')[1][:5] if 'T' in alert['timestamp'] else ""
            
            label = Label(f"{title}\n  {desc} ({time})")
            alerts_list.mount(ListItem(label))
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "run-btn":
            self.action_run_now()
        elif event.button.id == "clear-btn":
            self.action_clear_alerts()
        elif event.button.id == "settings-btn":
            self.action_settings()
    
    def action_run_now(self) -> None:
        """Run scan immediately."""
        self.app.notify("Running scan...")
        self.run_worker(self._run_scan_worker, thread=True)
    
    def _run_scan_worker(self) -> None:
        """Worker to run scan."""
        try:
            alerts = self.monitor.run_now()
            self.app.call_from_thread(self._scan_complete, len(alerts))
        except Exception as e:
            self.app.call_from_thread(self.app.notify, f"Scan failed: {e}")
    
    def _scan_complete(self, alert_count: int) -> None:
        """Handle scan completion."""
        self._update_status()
        self._load_alerts()
        self.app.notify(f"Scan complete. {alert_count} new alerts.")
    
    def action_clear_alerts(self) -> None:
        """Clear all alerts."""
        self.monitor.clear_alerts()
        self._load_alerts()
        self.app.notify("Alerts cleared")
    
    def action_settings(self) -> None:
        """Open settings screen."""
        from homeguard.tui.screens.settings import SettingsScreen
        self.app.push_screen(SettingsScreen())
    
    def action_go_back(self) -> None:
        """Go back to main screen."""
        self.app.pop_screen()
