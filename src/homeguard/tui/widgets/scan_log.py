"""Scan log widget."""

from textual.widgets import RichLog


class ScanLog(RichLog):
    """Real-time log for scan progress."""

    def __init__(self, **kwargs):
        super().__init__(highlight=True, markup=True, **kwargs)

    def log_tool_call(self, name: str, args: dict) -> None:
        """Log a tool call."""
        args_str = ", ".join(f"{k}={v}" for k, v in args.items()) if args else ""
        self.write(f"[dim]→[/dim] [cyan]{name}[/cyan]({args_str})")

    def log_device_found(self, ip: str, vendor: str) -> None:
        """Log device discovery."""
        self.write(f"[green]✓[/green] Found: [bold]{ip}[/bold] ({vendor})")

    def log_finding(self, finding: str, risk: str = "medium") -> None:
        """Log a security finding."""
        colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}
        color = colors.get(risk.lower(), "white")
        self.write(f"[{color}]⚠[/{color}] {finding}")

    def log_info(self, message: str) -> None:
        """Log info message."""
        self.write(f"[dim]{message}[/dim]")

    def log_error(self, message: str) -> None:
        """Log error message."""
        self.write(f"[red]✗ {message}[/red]")

    def log_complete(self, device_count: int) -> None:
        """Log scan completion."""
        self.write(f"\n[bold green]✓ Scan complete![/bold green] Found {device_count} devices.")
