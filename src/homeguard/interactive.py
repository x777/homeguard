"""Interactive menu for HomeGuard CLI."""

from rich.console import Console

console = Console()


def run_interactive():
    """Run the interactive TUI."""
    from homeguard.tui import HomeGuardApp
    app = HomeGuardApp()
    app.run()


# Keep old menu for fallback if needed
def run_interactive_legacy():
    """Run the legacy questionary-based menu."""
    import platform
    import questionary
    from rich.panel import Panel
    from rich.table import Table

    def show_banner():
        console.print(
            Panel.fit(
                "[bold cyan]🛡️ HomeGuard[/bold cyan]\n"
                "[dim]AI-Powered Network Security Assessment[/dim]",
                border_style="cyan",
            )
        )
        console.print()

    def main_menu() -> str:
        return questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("🛡️ Security Scan - AI analyzes your network", value="ai_scan"),
                questionary.Choice("⚙️  Settings", value="settings"),
                questionary.Choice("ℹ️  System Info - View network information", value="info"),
                questionary.Choice("❌ Exit", value="exit"),
            ],
        ).ask()

    def press_enter_to_continue():
        console.print("[dim]Press Enter to return to menu...[/dim]")
        input()

    from homeguard.scanner.discovery import get_local_ip, get_network_cidr, SCAPY_AVAILABLE

    while True:
        console.clear()
        show_banner()
        choice = main_menu()

        if choice == "exit" or choice is None:
            console.print("\n[cyan]Thanks for using HomeGuard! Stay safe! 👋[/cyan]\n")
            break

        elif choice == "info":
            local_ip = get_local_ip()
            network = get_network_cidr(local_ip)

            table = Table(title="System Information")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Operating System", platform.system())
            table.add_row("Local IP", local_ip)
            table.add_row("Network", network)
            table.add_row("Scapy Available", "✅ Yes" if SCAPY_AVAILABLE else "❌ No")
            
            from homeguard.agent.config import load_config
            config = load_config()
            if config:
                table.add_row("LLM Provider", f"{config.provider} ({config.model})")
            else:
                table.add_row("LLM Provider", "[yellow]Using backend proxy[/yellow]")
            
            console.print(table)

        elif choice == "ai_scan":
            from homeguard.agent import run_agent_interactive
            run_agent_interactive()

        elif choice == "settings":
            from homeguard.agent.config import load_config, save_config, setup_wizard, CONFIG_PATH

            existing = load_config()
            console.print("\n[bold]Settings[/bold]\n")

            if existing:
                console.print(f"LLM Provider: [cyan]{existing.provider}[/cyan] / [green]{existing.model}[/green]")
                console.print(f"Scan Mode:    [yellow]{existing.scan_mode}[/yellow]")
                console.print(f"Config file:  [dim]{CONFIG_PATH}[/dim]\n")

            action = questionary.select(
                "What would you like to configure?",
                choices=[
                    questionary.Choice("🔑 LLM Provider - Configure API key", value="llm"),
                    questionary.Choice(f"📊 Scan Mode - Currently: {existing.scan_mode}", value="scan_mode"),
                    questionary.Choice("🌐 Reset to defaults", value="reset"),
                    questionary.Choice("← Back", value="back"),
                ],
            ).ask()

            if action == "llm":
                setup_wizard()
                console.print("[green]✓ LLM configuration saved![/green]")
            elif action == "scan_mode":
                new_mode = questionary.select(
                    "Select scan mode:",
                    choices=[
                        questionary.Choice("Quick - 8 common ports (faster)", value="quick"),
                        questionary.Choice("Full - 25 ports (thorough)", value="full"),
                    ],
                ).ask()
                if new_mode:
                    existing.scan_mode = new_mode
                    save_config(existing)
                    console.print(f"[green]✓ Scan mode set to {new_mode}[/green]")
            elif action == "reset":
                import os
                if CONFIG_PATH.exists():
                    os.remove(CONFIG_PATH)
                console.print("[green]✓ Reset to defaults[/green]")

        console.print()
        press_enter_to_continue()
