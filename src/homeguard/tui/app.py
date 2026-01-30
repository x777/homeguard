"""HomeGuard TUI Application."""

from pathlib import Path
from textual.app import App

from homeguard.tui.screens import MainScreen, ScanScreen
from homeguard.monitor.scheduler import NetworkMonitor


class HomeGuardApp(App):
    """Main HomeGuard TUI application."""

    TITLE = "🛡️ HomeGuard"
    SUB_TITLE = "Network Security Scanner"
    CSS_PATH = Path(__file__).parent / "styles.tcss"
    
    SCREENS = {
        "main": MainScreen,
        "scan": ScanScreen,
    }
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan", "New Scan"),
        ("c", "toggle_chat", "Chat"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.monitor = NetworkMonitor()
        self.monitor.start()

    def on_mount(self) -> None:
        """Push main screen on mount."""
        self.push_screen("main")

    def action_scan(self) -> None:
        """Start a new scan."""
        self.push_screen("scan")

    def action_toggle_chat(self) -> None:
        """Toggle chat window (delegate to current screen)."""
        if hasattr(self.screen, "action_toggle_chat"):
            self.screen.action_toggle_chat()

    def action_quit(self) -> None:
        """Quit the application."""
        self.monitor.stop()
        self.exit()
