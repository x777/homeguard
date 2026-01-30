"""LLM settings screen for configuring backend and scan mode."""

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, Select

from homeguard.agent.config import load_config, save_config, LLMConfig
from homeguard.agent.constants import DEFAULT_BACKEND_URL


class LLMSettingsScreen(Screen):
    """Settings screen for LLM configuration."""
    
    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("s", "save", "Save"),
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.config = load_config()
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="llm-settings-container"):
            yield Static("⚙️ LLM Settings", classes="title")
            
            # Backend URL
            with Horizontal(classes="setting-row"):
                yield Static("Backend URL:", classes="setting-label")
                yield Input(
                    value=self.config.base_url or DEFAULT_BACKEND_URL,
                    placeholder=DEFAULT_BACKEND_URL,
                    id="base_url"
                )
            
            # Scan Mode
            with Horizontal(classes="setting-row"):
                yield Static("Default Scan Mode:", classes="setting-label")
                yield Select(
                    [("Quick (17 ports)", "quick"), ("Full (AI analysis)", "full")],
                    value=self.config.scan_mode,
                    id="scan_mode"
                )
            
            # Provider (read-only for now)
            with Horizontal(classes="setting-row"):
                yield Static("Provider:", classes="setting-label")
                yield Static(f"{self.config.provider} / {self.config.model}", id="provider_info")
            
            yield Static("\n💡 Tip: Leave Backend URL empty to use default", classes="hint")
            
            with Horizontal(classes="button-row"):
                yield Button("Save", variant="primary", id="save-btn")
                yield Button("Reset to Defaults", variant="warning", id="reset-btn")
                yield Button("Cancel", id="cancel-btn")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "reset-btn":
            self.action_reset()
        elif event.button.id == "cancel-btn":
            self.action_go_back()
    
    def action_save(self) -> None:
        """Save settings and go back."""
        base_url = self.query_one("#base_url", Input).value.strip()
        scan_mode = self.query_one("#scan_mode", Select).value
        
        # Update config
        self.config.base_url = base_url if base_url else None
        self.config.scan_mode = scan_mode
        
        # Save to file
        if save_config(self.config):
            self.app.notify("✅ Settings saved", severity="information")
        else:
            self.app.notify("❌ Failed to save settings", severity="error")
        
        self.app.pop_screen()
    
    def action_reset(self) -> None:
        """Reset to default settings."""
        from pathlib import Path
        from homeguard.agent.config import CONFIG_PATH
        
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()
            self.app.notify("✅ Reset to defaults", severity="information")
            self.app.pop_screen()
        else:
            self.app.notify("Already using defaults", severity="information")
    
    def action_go_back(self) -> None:
        """Go back without saving."""
        self.app.pop_screen()
