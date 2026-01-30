"""Chat window widget for LLM interaction."""

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import Input, Static
from textual.widget import Widget
from textual.message import Message


class ChatWindow(Widget):
    """Chat window for LLM interaction based on selected report."""
    
    DEFAULT_CSS = """
    ChatWindow {
        display: none;
        layer: overlay;
        dock: bottom;
        height: 60%;
        background: $surface;
        margin-bottom: 3;
        border-top: solid $primary;
    }
    
    ChatWindow.visible {
        display: block;
    }
    
    ChatWindow.modal {
        layer: above;
        background: $surface;
    }
    
    #chat-header {
        dock: top;
        height: 3;
        background: $primary;
        color: $text;
        text-align: center;
        padding: 1;
    }
    
    #chat-messages {
        height: 1fr;
        scrollbar-gutter: stable;
        padding: 1;
        background: $surface;
    }
    
    #chat-input {
        dock: bottom;
        height: 3;
        margin: 1;
        border: round $primary;
    }
    
    .message {
        margin-bottom: 1;
        padding: 1 2;
    }
    
    .user-message {
        background: $primary;
        color: $text;
        text-align: right;
        margin-left: 10;
    }
    
    .assistant-message {
        background: $surface-lighten-2;
        color: $text;
        margin-right: 10;
        border-left: thick $accent;
    }
    
    .loading-message {
        background: $surface-lighten-1;
        color: $text-muted;
        margin-right: 10;
        border-left: thick $warning;
    }
    """
    
    class ChatSubmit(Message):
        """Message sent when user submits chat input."""
        def __init__(self, message: str) -> None:
            self.message = message
            super().__init__()
    
    def __init__(self, report_context: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.report_context = report_context
        self.is_visible = False
        self.current_report_id = None
    
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("💬 Chat with AI Assistant (Press 'Esc' to close)", id="chat-header")
            yield VerticalScroll(id="chat-messages")
            yield Input(placeholder="Ask about the security findings...", id="chat-input")
    
    def toggle_visibility(self) -> None:
        """Toggle chat window visibility."""
        self.is_visible = not self.is_visible
        if self.is_visible:
            self.add_class("visible")
            self.add_class("modal")
            self.query_one("#chat-input").focus()
        else:
            self.remove_class("visible")
            self.remove_class("modal")
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle chat input submission."""
        if event.input.id == "chat-input":
            message = event.value.strip()
            if message:
                self.add_user_message(message)
                self.post_message(self.ChatSubmit(message))
                event.input.value = ""
    
    def add_user_message(self, message: str) -> None:
        """Add user message to chat."""
        messages = self.query_one("#chat-messages")
        messages.mount(Static(f"You: {message}", classes="message user-message"))
        messages.scroll_end()
    
    def add_assistant_message(self, message: str) -> None:
        """Add assistant message to chat."""
        messages = self.query_one("#chat-messages")
        messages.mount(Static(f"AI: {message}", classes="message assistant-message"))
        messages.scroll_end()
    
    def add_loading_indicator(self) -> None:
        """Add loading indicator while waiting for response."""
        messages = self.query_one("#chat-messages")
        loading = Static("🤔 Thinking...", classes="message loading-message", id="loading-indicator")
        messages.mount(loading)
        messages.scroll_end()
    
    def remove_loading_indicator(self) -> None:
        """Remove loading indicator."""
        try:
            loading = self.query_one("#loading-indicator")
            loading.remove()
        except Exception:
            pass
    
    def on_key(self, event) -> None:
        """Handle key presses when chat is visible."""
        if self.is_visible and event.key == "escape":
            self.toggle_visibility()
            event.prevent_default()
    
    def set_report_context(self, context: str, report_id: str = None) -> None:
        """Update the report context for the chat."""
        # If switching reports while chat is open, reset conversation
        if report_id and self.current_report_id and report_id != self.current_report_id:
            self.clear_messages()
        
        self.report_context = context
        self.current_report_id = report_id
    
    def clear_messages(self) -> None:
        """Clear all chat messages."""
        messages = self.query_one("#chat-messages")
        for child in list(messages.children):
            child.remove()
