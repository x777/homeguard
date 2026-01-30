"""Modal for reviewing and executing vulnerability fixes."""

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static, Label
from textual.message import Message


class FixModal(ModalScreen):
    """Modal to review and execute fixes."""
    
    class FixConfirmed(Message):
        """Emitted when user confirms fixes."""
        def __init__(self, device: dict, vulnerabilities: list):
            self.device = device
            self.vulnerabilities = vulnerabilities
            super().__init__()
    
    def __init__(self, device: dict, vulnerabilities: list):
        super().__init__()
        self.device = device
        self.vulnerabilities = vulnerabilities
    
    def compose(self) -> ComposeResult:
        """Create modal layout."""
        ip = self.device.get("ip", "Unknown")
        
        with Container(id="fix_dialog"):
            yield Label(f"Fix Issues: {ip}", id="fix_title")
            
            with Vertical(id="fix_content"):
                yield Static(f"Found {len(self.vulnerabilities)} fixable vulnerabilities:\n")
                
                for vuln in self.vulnerabilities:
                    severity = vuln.get("severity", "medium")
                    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "⚪")
                    desc = vuln.get("description", "Unknown issue")
                    method = vuln.get("fix_type", "unknown")
                    yield Static(f"{icon} {desc}\n   Method: {method}")
                
                yield Static("\n⚠️  Warning: This will modify device configuration.")
                yield Static("Ensure you have backup access before proceeding.\n")
            
            with Container(id="fix_buttons"):
                yield Button("Execute Fixes", variant="success", id="confirm")
                yield Button("Cancel", variant="default", id="cancel")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "confirm":
            self.post_message(self.FixConfirmed(self.device, self.vulnerabilities))
            self.dismiss()
        else:
            self.dismiss()
