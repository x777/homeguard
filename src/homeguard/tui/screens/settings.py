"""Settings screen for monitoring configuration."""

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Switch, Select, Input, Button

from homeguard.monitor.settings import MonitorSettings


class SettingsScreen(Screen):
    """Settings screen for monitoring configuration."""
    
    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("s", "save", "Save"),
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.settings = MonitorSettings()
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="settings-container"):
            yield Static("⚙️ Monitoring Settings", classes="title")
            
            # Enable/Disable
            with Horizontal(classes="setting-row"):
                yield Static("Enable Monitoring:", classes="setting-label")
                yield Switch(value=self.settings.get("enabled"), id="enabled")
            
            # Scan Interval
            with Horizontal(classes="setting-row"):
                yield Static("Scan Interval:", classes="setting-label")
                yield Select(
                    [("1 hour", 1), ("3 hours", 3), ("6 hours", 6), ("12 hours", 12), ("24 hours", 24)],
                    value=self.settings.get("interval_hours", 6),
                    id="interval"
                )
            
            yield Static("🔔 Alert Types", classes="section-title")
            
            with Horizontal(classes="setting-row"):
                yield Static("New Devices:", classes="setting-label")
                yield Switch(value=self.settings.get("alert_new_devices"), id="alert_new_devices")
            
            with Horizontal(classes="setting-row"):
                yield Static("Vulnerabilities:", classes="setting-label")
                yield Switch(value=self.settings.get("alert_vulnerabilities"), id="alert_vulnerabilities")
            
            with Horizontal(classes="setting-row"):
                yield Static("Config Changes:", classes="setting-label")
                yield Switch(value=self.settings.get("alert_config_changes"), id="alert_config_changes")
            
            with Horizontal(classes="setting-row"):
                yield Static("Port Changes:", classes="setting-label")
                yield Switch(value=self.settings.get("alert_port_changes"), id="alert_port_changes")
            
            yield Static("📬 Notifications", classes="section-title")
            
            with Horizontal(classes="setting-row"):
                yield Static("Desktop Notifications:", classes="setting-label")
                yield Switch(value=self.settings.get("notification_desktop"), id="notification_desktop")
            
            with Horizontal(classes="setting-row"):
                yield Static("Telegram Notifications:", classes="setting-label")
                yield Switch(value=self.settings.get("notification_telegram"), id="notification_telegram")
            
            with Horizontal(classes="setting-row"):
                yield Static("Telegram Bot Token:", classes="setting-label")
                yield Input(value=self.settings.get("telegram_bot_token", ""), placeholder="123456:ABC-DEF...", id="telegram_bot_token")
            
            with Horizontal(classes="setting-row"):
                yield Static("Telegram Chat ID:", classes="setting-label")
                yield Input(value=self.settings.get("telegram_chat_id", ""), placeholder="123456789", id="telegram_chat_id")
            
            with Horizontal(classes="setting-row"):
                yield Static("Minimum Severity:", classes="setting-label")
                yield Select(
                    [("Low", "low"), ("Medium", "medium"), ("High", "high"), ("Critical", "critical")],
                    value=self.settings.get("min_severity", "medium"),
                    id="min_severity"
                )
            
            with Horizontal(classes="button-row"):
                yield Button("Save", variant="primary", id="save-btn")
                yield Button("Cancel", id="cancel-btn")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "cancel-btn":
            self.action_go_back()
    
    def action_save(self) -> None:
        """Save settings and go back."""
        # Collect values
        enabled = self.query_one("#enabled", Switch).value
        
        self.settings.update(
            enabled=enabled,
            interval_hours=self.query_one("#interval", Select).value,
            alert_new_devices=self.query_one("#alert_new_devices", Switch).value,
            alert_vulnerabilities=self.query_one("#alert_vulnerabilities", Switch).value,
            alert_config_changes=self.query_one("#alert_config_changes", Switch).value,
            alert_port_changes=self.query_one("#alert_port_changes", Switch).value,
            notification_desktop=self.query_one("#notification_desktop", Switch).value,
            notification_telegram=self.query_one("#notification_telegram", Switch).value,
            telegram_bot_token=self.query_one("#telegram_bot_token", Input).value,
            telegram_chat_id=self.query_one("#telegram_chat_id", Input).value,
            min_severity=self.query_one("#min_severity", Select).value,
        )
        
        # Restart monitor if enabled
        if enabled:
            monitor = self.app.monitor
            monitor.stop()
            monitor.start()
            self.app.notify("Settings saved - Monitoring started")
        else:
            self.app.monitor.stop()
            self.app.notify("Settings saved - Monitoring stopped")
        
        self.app.pop_screen()
    
    def action_go_back(self) -> None:
        """Go back without saving."""
        self.app.pop_screen()
