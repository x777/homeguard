"""HomeGuard CLI - Network Security Assessment Tool."""

import json
import platform
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from homeguard.scanner.discovery import (
    scan_network,
    get_local_ip,
    get_network_cidr,
    SCAPY_AVAILABLE,
)
from homeguard.scanner.ports import scan_ports
from homeguard.scanner.services import get_risk_color

app = typer.Typer(
    name="homeguard",
    help="🛡️ HomeGuard - Network Security Assessment Tool",
    add_completion=False,
    invoke_without_command=True,
)
console = Console()


@app.command()
def scan(
    network: Optional[str] = typer.Option(
        None, "--network", "-n", help="Network to scan in CIDR notation"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
    timeout: int = typer.Option(3, "--timeout", "-t", help="Scan timeout in seconds"),
    no_scapy: bool = typer.Option(False, "--no-scapy", help="Disable scapy"),
    with_ports: bool = typer.Option(False, "--ports", "-p", help="Also scan for open ports"),
):
    """🔍 Scan your network for connected devices."""
    if not network:
        local_ip = get_local_ip()
        network = get_network_cidr(local_ip)
        console.print(f"[dim]Auto-detected network:[/dim] [cyan]{network}[/cyan]")

    if SCAPY_AVAILABLE and not no_scapy:
        console.print("[dim]Scanner:[/dim] [green]scapy (ARP)[/green] + ping fallback")
    else:
        console.print("[dim]Scanner:[/dim] [yellow]ping sweep[/yellow]")

    console.print()

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        progress.add_task(f"Scanning {network}...", total=None)
        result = scan_network(network=network, use_scapy=not no_scapy, timeout=timeout)

    if not result.devices:
        console.print("[yellow]No devices found.[/yellow]")
        console.print("[dim]Try running with sudo for better results.[/dim]")
        return

    # Port scan if requested
    if with_ports:
        console.print()
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as progress:
            task = progress.add_task("Scanning ports...", total=len(result.devices))
            for device in result.devices:
                progress.update(task, description=f"Scanning ports on {device.ip}...")
                device.ports = scan_ports(device.ip, quick=True)
                
                # Add fingerprinting to CLI
                try:
                    from homeguard.agent.tools import execute_tool, identify_device_type
                    
                    # Basic device data for fingerprinting
                    device_data = {
                        "ip": device.ip,
                        "mac": device.mac,
                        "device_type": "Unknown",
                        "vendor": "Unknown",
                        "open_ports": [{"port": p.port} for p in device.ports],
                        "os_guess": device.os_guess or "Unknown"
                    }
                    
                    # Identify device type
                    port_numbers = [p.port for p in device.ports]
                    device_info = identify_device_type(device.ip, device.mac, port_numbers, device.os_guess)
                    device_data["device_type"] = device_info.get("device_type", "Unknown")
                    device_data["vendor"] = device_info.get("vendor", "Unknown")
                    
                    # Create fingerprint
                    fp_result = execute_tool("fingerprint_device", {"ip": device.ip, "action": "create", "device_data": device_data})
                    if fp_result and fp_result.success:
                        device.fingerprint_id = fp_result.data.get("fingerprint_id", "")[:8]
                except Exception:
                    device.fingerprint_id = ""
                
                progress.advance(task)

    # Display results
    table = Table(title=f"🖥️  Devices on {result.network}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="magenta")
    table.add_column("Hostname", style="green")
    table.add_column("OS (TTL)", style="yellow")
    table.add_column("TTL", justify="right")
    if with_ports:
        table.add_column("Open Ports", style="red")
        table.add_column("Fingerprint", style="dim")

    for device in result.devices:
        row = [
            device.ip,
            device.mac,
            device.hostname or "-",
            device.os_guess or "Unknown",
            str(device.ttl) if device.ttl else "-",
        ]
        if with_ports:
            ports_str = ", ".join(str(p.port) for p in device.ports) if device.ports else "-"
            row.append(ports_str)
            fp_id = getattr(device, 'fingerprint_id', '')
            row.append(fp_id if fp_id else "-")
        table.add_row(*row)

    console.print(table)
    console.print(f"\n[dim]Found {len(result.devices)} device(s)[/dim]")

    if output:
        with open(output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def ports(
    target: str = typer.Argument(..., help="Target IP address to scan"),
    quick: bool = typer.Option(True, "--quick/--full", "-q/-f", help="Quick vs full scan"),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Timeout per port"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
):
    """🔓 Scan a target for open ports."""
    console.print(f"[dim]Target:[/dim] [cyan]{target}[/cyan]")
    console.print(f"[dim]Mode:[/dim] [yellow]{'Quick (8 ports)' if quick else 'Full (25 ports)'}[/yellow]")
    console.print()

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        progress.add_task(f"Scanning {target}...", total=None)
        results = scan_ports(target, quick=quick, timeout=timeout)

    if not results:
        console.print("[green]No open ports found.[/green]")
        return

    table = Table(title=f"🔓 Open Ports on {target}")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Risk", justify="center")
    table.add_column("Banner", style="dim")

    for p in results:
        risk_color = get_risk_color(p.risk)
        table.add_row(
            str(p.port),
            p.service,
            f"[{risk_color}]{p.risk.upper()}[/{risk_color}]",
            (p.banner[:40] + "...") if p.banner and len(p.banner) > 40 else (p.banner or "-"),
        )

    console.print(table)
    console.print(f"\n[dim]Found {len(results)} open port(s)[/dim]")

    if output:
        with open(output, "w") as f:
            json.dump([p.to_dict() for p in results], f, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def info():
    """ℹ️  Show system and network information."""
    local_ip = get_local_ip()
    network = get_network_cidr(local_ip)

    table = Table(title="System Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Operating System", platform.system())
    table.add_row("OS Version", platform.version())
    table.add_row("Local IP", local_ip)
    table.add_row("Network", network)
    table.add_row("Scapy Available", "✅ Yes" if SCAPY_AVAILABLE else "❌ No")

    console.print(table)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """🛡️ HomeGuard CLI - Network Security Assessment Tool"""
    if ctx.invoked_subcommand is None:
        # No command provided - run interactive mode
        from homeguard.interactive import run_interactive
        run_interactive()


if __name__ == "__main__":
    app()
