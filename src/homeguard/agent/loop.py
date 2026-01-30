"""Agent loop with human-in-the-loop safety."""

import json
import re
import warnings
from datetime import datetime

import httpx
import questionary
from rich.console import Console
from rich.panel import Panel

from typing import Optional, Dict, List, Tuple, Any

from .config import LLMConfig, load_config
from .constants import DEFAULT_BACKEND_URL, MAX_SCAN_ITERATIONS
from .llm import SYSTEM_PROMPT, chat_with_tools, extract_tool_calls, get_response_text
from .tools import execute_tool, get_tool_risk, format_tool_result, RiskLevel, ToolResult
from .report import ScanReport, DeviceReport, generate_scan_id, save_report, format_cli_report
from .scan_orchestrator import ScanOrchestrator

warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

console = Console()


# === UI Helpers ===

def _show_thinking(text: str) -> None:
    if text:
        console.print(Panel(text, title="🤖 AI", border_style="cyan"))


def _show_tool_call(name: str, args: Dict[str, Any]) -> None:
    args_str = ", ".join(f"{k}={v}" for k, v in args.items()) if args else ""
    console.print(f"[dim]→ Calling:[/dim] [cyan]{name}[/cyan]({args_str})")


def _request_approval(name: str, args: Dict[str, Any], risk: RiskLevel) -> str:
    colors = {RiskLevel.LOW: "green", RiskLevel.MEDIUM: "yellow", RiskLevel.HIGH: "orange1", RiskLevel.CRITICAL: "red"}
    color = colors[risk]
    console.print(Panel(
        f"[bold]Action:[/bold] {name}\n[bold]Risk Level:[/bold] [{color}]{risk.value.upper()}[/{color}]\n\n[bold]Details:[/bold]\n{json.dumps(args, indent=2)}",
        title="🤖 AI wants to perform an action", border_style=color,
    ))
    choice = questionary.select("Allow this action?", choices=[
        questionary.Choice("✅ Yes, proceed", value="yes"),
        questionary.Choice("❌ No, skip this", value="no"),
        questionary.Choice("🛑 Stop AI scan", value="stop"),
    ]).ask()
    return choice or "no"


def _show_fix_suggestion(issue: str, command: str, explanation: str) -> str:
    console.print(Panel(
        f"[bold]Issue:[/bold] {issue}\n\n[bold]Suggested Command:[/bold]\n[cyan]{command}[/cyan]\n\n[bold]Explanation:[/bold] {explanation}",
        title="🔧 Suggested Fix", border_style="yellow",
    ))
    choice = questionary.select("What would you like to do?", choices=[
        questionary.Choice("📋 Copy command", value="copy"),
        questionary.Choice("📝 Note it for later", value="note"),
        questionary.Choice("❌ Skip", value="skip"),
    ]).ask()
    if choice == "copy":
        try:
            import pyperclip
            pyperclip.copy(command)
            console.print("[green]✓ Copied to clipboard[/green]")
        except ImportError:
            console.print(f"[yellow]Command:[/yellow] {command}")
    return choice or "skip"


# === Scan Data Handlers ===

def _handle_scan_network(result: ToolResult, scan_data: Dict[str, Any], orchestrator: ScanOrchestrator) -> None:
    """Process scan_network results."""
    orchestrator.handle_scan_network(result.data, scan_data)


def _handle_scan_ports(ip: str, result: ToolResult, scan_data: Dict[str, Any], backend_url: str, orchestrator: ScanOrchestrator) -> None:
    """Process scan_ports results and run auto checks."""
    device_type, port_numbers = orchestrator.handle_scan_ports(ip, result.data, scan_data)
    
    # Update result data
    result.data["device_type"] = device_type
    
    # Run deep scan
    deep_scan_result = orchestrator.run_deep_scan(ip, device_type, port_numbers, scan_data["device_map"][ip])
    if deep_scan_result:
        result.data["deep_scan"] = deep_scan_result
    
    # Run security checks for web devices
    if any(p.get("port") in [80, 443, 8080, 8443] for p in result.data.get("open_ports", [])):
        orchestrator.run_security_checks(ip, scan_data["device_map"][ip])
    
    # Query threat intel
    orchestrator.run_threat_intel(ip, device_type, scan_data["device_map"][ip])


def _run_deep_scan(ip: str, device_type: str, port_numbers: List[int], scan_data: Dict[str, Any]) -> None:
    """Run appropriate deep scan based on device type."""
    deep_scan_result = None
    
    if "Router" in device_type:
        console.print(f"[dim]→ Auto deep scan:[/dim] [cyan]deep_scan_router[/cyan]({ip})")
        deep_scan_result = execute_tool("deep_scan_router", {"ip": ip})
        if deep_scan_result and deep_scan_result.success:
            http_info = deep_scan_result.data.get("http_info", {})
            vendor = extract_vendor_from_scan_data(deep_scan_result.data, http_info)
            if vendor != "Unknown":
                scan_data["device_map"][ip]["vendor"] = vendor
                console.print(f"[dim]   Vendor detected:[/dim] [green]{vendor}[/green]")
        # Router-specific checks
        for check in ["check_upnp_exposure", "check_dns_hijacking"]:
            console.print(f"[dim]→ Auto check:[/dim] [cyan]{check}[/cyan]({ip})")
            check_result = execute_tool(check, {"ip": ip})
            if check_result and check_result.success:
                key = "upnp_check" if "upnp" in check else "dns_check"
                scan_data["device_map"][ip][key] = check_result.data
                
    elif device_type in ["IoT Device", "Smart TV / Streaming Device", "IP Camera"]:
        console.print(f"[dim]→ Auto deep scan:[/dim] [cyan]deep_scan_iot[/cyan]({ip})")
        deep_scan_result = execute_tool("deep_scan_iot", {"ip": ip})
        
    elif device_type in ["NAS / Storage", "Server"]:
        console.print(f"[dim]→ Auto deep scan:[/dim] [cyan]deep_scan_storage[/cyan]({ip})")
        deep_scan_result = execute_tool("deep_scan_storage", {"ip": ip})
        
    elif device_type == "Unknown Device":
        console.print(f"[dim]→ Auto probe:[/dim] [cyan]probe_unknown_device[/cyan]({ip})")
        deep_scan_result = execute_tool("probe_unknown_device", {"ip": ip, "known_ports": port_numbers})
        if deep_scan_result and deep_scan_result.success:
            probed_type = deep_scan_result.data.get("possible_type", "Unknown")
            if probed_type != "Unknown":
                scan_data["device_map"][ip]["device_type"] = probed_type
    
    # Extract vendor from deep scan
    if deep_scan_result and deep_scan_result.success:
        http_info = deep_scan_result.data.get("http_info", {})
        banners = deep_scan_result.data.get("banners", {})
        vendor = extract_vendor_from_scan_data(deep_scan_result.data, http_info, banners)
        if vendor != "Unknown":
            scan_data["device_map"][ip]["vendor"] = vendor
            console.print(f"[dim]   Vendor detected:[/dim] [green]{vendor}[/green]")
    
    return deep_scan_result


def _run_security_checks(ip: str, scan_data: Dict[str, Any]) -> None:
    """Run security checks on devices with web interfaces."""
    # Model detection
    console.print(f"[dim]→ Auto detect:[/dim] [cyan]detect_device_model[/cyan]({ip})")
    model_info = detect_device_model(ip)
    if model_info.get("model"):
        scan_data["device_map"][ip]["model"] = model_info["model"]
        console.print(f"[dim]   Model detected:[/dim] [green]{model_info['model']}[/green]")
    if model_info.get("firmware"):
        scan_data["device_map"][ip]["firmware_version"] = model_info["firmware"]
        console.print(f"[dim]   Firmware:[/dim] [yellow]{model_info['firmware']}[/yellow]")
    
    # Encryption and firmware checks
    for check, key in [("check_encryption", "encryption_check"), ("check_firmware_age", "firmware_check")]:
        console.print(f"[dim]→ Auto check:[/dim] [cyan]{check}[/cyan]({ip})")
        result = execute_tool(check, {"ip": ip})
        if result and result.success:
            scan_data["device_map"][ip][key] = result.data


def _run_threat_intel(ip: str, device_type: str, scan_data: Dict[str, Any], backend_url: str) -> None:
    """Query threat intelligence for device."""
    vendor = scan_data["device_map"][ip].get("vendor", "Unknown")
    model = scan_data["device_map"][ip].get("model")
    
    if vendor and vendor != "Unknown":
        search_vendor = _normalize_vendor_name(vendor)
        search_term = f"{search_vendor} {model}" if model else search_vendor
        console.print(f"[dim]→ Auto check:[/dim] [cyan]check_threat_intel[/cyan]({search_term})")
        ti_result = execute_tool("check_threat_intel", {"ip": ip, "check_type": "vendor", "vendor": search_term}, backend_url=backend_url)
        if ti_result and ti_result.success:
            scan_data["device_map"][ip]["threat_intel"] = ti_result.data
    
    # IoT-specific exploits
    if device_type in ["IoT Device", "Smart TV / Streaming Device", "IP Camera"]:
        search_vendor = _normalize_vendor_name(vendor) if vendor != "Unknown" else "generic"
        iot_search = f"{search_vendor} {model}" if model else search_vendor
        console.print(f"[dim]→ Auto check:[/dim] [cyan]check_threat_intel[/cyan](iot={iot_search})")
        ti_result = execute_tool("check_threat_intel", {"ip": ip, "check_type": "iot", "vendor": iot_search}, backend_url=backend_url)
        if ti_result and ti_result.success:
            existing = scan_data["device_map"][ip].get("threat_intel", {})
            existing["iot_exploits"] = ti_result.data.get("exploits", [])
            scan_data["device_map"][ip]["threat_intel"] = existing


# === Report Generation ===

def _generate_findings(scan_data: Dict[str, Any]) -> Tuple[List[str], List[str], Dict[str, int], str]:
    """Generate findings and recommendations from scan data."""
    findings, recommendations = [], []
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for device in scan_data["devices"]:
        ip, device_type = device.get("ip", ""), device.get("device_type", "Unknown")
        device_risks = []
        
        for port in device.get("open_ports", []):
            port_num = port.get("port")
            risk = port.get("risk", "low")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            if risk == "critical":
                if port_num == 445:
                    findings.append(f"🔴 CRITICAL: {device_type} ({ip}) has SMB exposed - ransomware risk")
                elif port_num == 23:
                    findings.append(f"🔴 CRITICAL: {device_type} ({ip}) has Telnet open")
                device_risks.append("critical")
            elif risk == "high":
                if port_num in [3306, 5432, 27017]:
                    findings.append(f"🟠 HIGH: {device_type} ({ip}) has database exposed")
                device_risks.append("high")
            elif risk == "medium":
                if port_num == 80 and "Router" in device_type:
                    findings.append(f"🟡 MEDIUM: Router ({ip}) has HTTP admin exposed")
                    recommendations.append("Access router admin via HTTPS instead of HTTP")
                elif port_num == 22:
                    findings.append(f"🟡 MEDIUM: {device_type} ({ip}) has SSH exposed")
                device_risks.append("medium")
        
        device["risks"] = device_risks
    
    # Determine overall risk
    if risk_counts["critical"] > 0:
        overall_risk = "critical"
    elif risk_counts["high"] > 0:
        overall_risk = "high"
    elif risk_counts["medium"] > 0:
        overall_risk = "medium"
    else:
        overall_risk = "low"
    
    if not findings:
        findings.append("✅ No critical security issues found")
    
    return findings, recommendations, risk_counts, overall_risk


def _generate_llm_recommendations(scan_data: Dict[str, Any], backend_url: str) -> List[str]:
    """Use LLM to generate recommendations based on all scan data."""
    summary = "Network scan results:\n\n"
    for device in scan_data.get("devices", []):
        summary += f"Device: {device.get('ip')} - {device.get('device_type', 'Unknown')}\n"
        summary += f"  Vendor: {device.get('vendor', 'Unknown')}\n"
        if device.get('model'):
            summary += f"  Model: {device.get('model')}\n"
        if device.get('open_ports'):
            ports = [f"{p.get('port')}/{p.get('service', '?')}" for p in device['open_ports']]
            summary += f"  Ports: {', '.join(ports)}\n"
        if device.get('threat_intel', {}).get('advisories'):
            advs = device['threat_intel']['advisories']
            critical = sum(1 for a in advs if a.get('severity') == 'CRITICAL')
            summary += f"  CVEs: {len(advs)} ({critical} critical)\n"
        summary += "\n"
    
    prompt = f"""You are a cybersecurity consultant. Generate prioritized security recommendations based on the network scan results.

## SCAN SUMMARY
{summary}

## RECOMMENDATION REQUIREMENTS
1. Prioritize by risk level: CRITICAL → HIGH → MEDIUM → LOW
2. Be device-specific: mention exact IP addresses and device types
3. Provide actionable steps, not generic advice
4. Include urgency indicators
5. Limit to 5-8 most important recommendations

## OUTPUT FORMAT
Respond with ONLY a JSON array of strings with priority indicators:
["🔴 CRITICAL: Update router firmware at 192.168.1.1 - 3 CVEs found", "🟠 HIGH: Disable Telnet on IoT device at 192.168.1.50"]

## PRIORITY LEVELS
- 🔴 CRITICAL: Immediate action required (exposed services, known exploits)
- 🟠 HIGH: Action needed within 24 hours (weak encryption, default creds)
- 🟡 MEDIUM: Action needed within 1 week (missing updates, config issues)
- 🟢 LOW: Best practice improvements (monitoring, documentation)"""
    try:
        response = httpx.post(f"{backend_url}/api/chat", json={"messages": [{"role": "user", "content": prompt}]}, timeout=30.0)
        response.raise_for_status()
        content = response.json().get("message", {}).get("content", "")
        match = re.search(r'\[.*\]', content, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception as e:
        console.print(f"[dim]Could not generate AI recommendations: {e}[/dim]")
    return []


def _build_device_report(device_data: Dict[str, Any]) -> DeviceReport:
    """Build a DeviceReport from device data."""
    return DeviceReport(
        ip=device_data.get("ip", ""),
        mac=device_data.get("mac", "Unknown"),
        device_type=device_data.get("device_type", "Unknown"),
        vendor=device_data.get("vendor", "Unknown"),
        os_guess=device_data.get("os_guess", "Unknown"),
        model=device_data.get("model", ""),
        firmware_version=device_data.get("firmware_version", ""),
        open_ports=device_data.get("open_ports", []),
        risks=device_data.get("risks", []),
        recommendations=device_data.get("recommendations", []),
        deep_scan=device_data.get("deep_scan", {}),
        encryption_check=device_data.get("encryption_check", {}),
        firmware_check=device_data.get("firmware_check", {}),
        upnp_check=device_data.get("upnp_check", {}),
        dns_check=device_data.get("dns_check", {}),
        threat_intel=device_data.get("threat_intel", {}),
        llm_identification=device_data.get("llm_identification", {}),
    )


def _save_final_report(scan_data: Dict[str, Any], backend_url: str) -> None:
    """Generate and save the final report."""
    scan_data["devices"] = list(scan_data["device_map"].values())
    if not scan_data["devices"]:
        return
    
    findings, recommendations, risk_counts, overall_risk = _generate_findings(scan_data)
    
    report = ScanReport(
        scan_id=generate_scan_id(),
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        network=scan_data.get("network", "Unknown"),
        scan_mode=scan_data.get("scan_mode", "quick"),
        total_devices=len(scan_data["devices"]),
        overall_findings=findings,
        overall_recommendations=recommendations,
        overall_risk=overall_risk,
        risk_summary=risk_counts,
    )
    
    for device_data in scan_data["devices"]:
        report.devices.append(_build_device_report(device_data))
    
    # LLM recommendations
    console.print("[dim]→ Generating AI recommendations...[/dim]")
    llm_recs = _generate_llm_recommendations(scan_data, backend_url)
    if llm_recs:
        report.overall_recommendations = llm_recs
    
    save_report(report)
    console.print()
    console.print(format_cli_report(report))


# === Main Agent Loop ===

def _initialize_scan(config: LLMConfig) -> Tuple[str, Dict[str, Any], List[Dict[str, str]], ScanOrchestrator]:
    """Initialize scan data and message history."""
    backend_url = config.base_url or DEFAULT_BACKEND_URL
    scan_data = {"network": "Unknown", "scan_mode": config.scan_mode, "devices": [], "device_map": {}}
    
    system_prompt = SYSTEM_PROMPT + f"\n\nScan mode is set to '{config.scan_mode}'."
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Scan my network with {config.scan_mode} mode. Discover devices, then analyze each one."},
    ]
    orchestrator = ScanOrchestrator(backend_url)
    return backend_url, scan_data, messages, orchestrator


def _handle_special_tool(name: str, args: Dict[str, Any], tool_id: str, scan_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Handle generate_report and suggest_fix tools."""
    if name == "generate_report":
        report = build_report_from_findings(
            args.get("findings", []), 
            args.get("recommendations", []), 
            args.get("risk_level", "low"), 
            scan_data
        )
        filepath = save_report(report)
        console.print(format_cli_report(report))
        return {"tool_call_id": tool_id, "content": f"Report saved to {filepath}"}
    
    if name == "suggest_fix":
        choice = _show_fix_suggestion(args.get("issue", ""), args.get("command", ""), args.get("explanation", ""))
        return {"tool_call_id": tool_id, "content": f"User chose: {choice}"}
    
    return None


def _execute_auto_approved_tool(name: str, args: Dict[str, Any], tool_id: str, scan_data: Dict[str, Any], backend_url: str, orchestrator: ScanOrchestrator) -> Dict[str, str]:
    """Execute auto-approved tool and update scan data."""
    _show_tool_call(name, args)
    result = execute_tool(name, args, backend_url=backend_url)
    
    if name == "scan_network" and result.success:
        _handle_scan_network(result, scan_data, orchestrator)
    elif name == "scan_ports" and result.success:
        _handle_scan_ports(args.get("ip"), result, scan_data, backend_url, orchestrator)
    elif name == "identify_device" and result.success:
        ip = args.get("ip")
        if ip in scan_data["device_map"]:
            scan_data["device_map"][ip].update({
                "device_type": result.data.get("device_type", "Unknown"),
                "vendor": result.data.get("vendor", "Unknown"),
            })
    
    return {"tool_call_id": tool_id, "content": format_tool_result(result)}


def _execute_tool_with_approval(name: str, args: Dict[str, Any], tool_id: str, risk: RiskLevel, backend_url: str) -> Tuple[Dict[str, str], bool]:
    """Execute tool after requesting user approval."""
    approval = _request_approval(name, args, risk)
    
    if approval == "yes":
        result = execute_tool(name, args, backend_url=backend_url)
        return {"tool_call_id": tool_id, "content": format_tool_result(result)}, False
    elif approval == "stop":
        return {"tool_call_id": tool_id, "content": "User stopped the scan."}, True
    else:
        return {"tool_call_id": tool_id, "content": "User denied this action."}, False


def _execute_tool_calls(tool_calls: List[Dict[str, Any]], scan_data: Dict[str, Any], backend_url: str, orchestrator: ScanOrchestrator) -> Tuple[List[Dict[str, str]], bool]:
    """Execute all tool calls with approval flow."""
    tool_results = []
    stop_requested = False

    for tc in tool_calls:
        name, args, tool_id = tc["name"], tc["arguments"], tc["id"]

        # Handle special tools
        special_result = _handle_special_tool(name, args, tool_id, scan_data)
        if special_result:
            tool_results.append(special_result)
            continue

        risk, auto_approve = get_tool_risk(name)

        if auto_approve:
            result = _execute_auto_approved_tool(name, args, tool_id, scan_data, backend_url, orchestrator)
            tool_results.append(result)
        else:
            result, stop = _execute_tool_with_approval(name, args, tool_id, risk, backend_url)
            tool_results.append(result)
            if stop:
                stop_requested = True
                break

    scan_data["devices"] = list(scan_data["device_map"].values())
    return tool_results, stop_requested


def _update_message_history(messages: List[Dict[str, Any]], response: Any, tool_results: List[Dict[str, str]]) -> None:
    """Append assistant message and tool results to history."""
    assistant_msg = {"role": "assistant", "content": response.choices[0].message.content}
    if response.choices[0].message.tool_calls:
        assistant_msg["tool_calls"] = [
            {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in response.choices[0].message.tool_calls
        ]
    messages.append(assistant_msg)
    for tr in tool_results:
        messages.append({"role": "tool", "tool_call_id": tr["tool_call_id"], "content": tr["content"]})


def run_agent(config: LLMConfig) -> None:
    """Run the AI agent loop."""
    console.print(Panel("🤖 Starting AI Security Scan...", style="cyan"))
    console.print(f"[dim]Scan mode: {config.scan_mode}[/dim]\n")

    backend_url, scan_data, messages, orchestrator = _initialize_scan(config)

    for _ in range(MAX_SCAN_ITERATIONS):
        try:
            response = chat_with_tools(messages, config)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            break

        text = get_response_text(response)
        if text:
            _show_thinking(text)

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            break

        tool_results, stop_requested = _execute_tool_calls(tool_calls, scan_data, backend_url, orchestrator)
        
        if stop_requested:
            console.print("\n[yellow]AI scan stopped by user.[/yellow]")
            break

        _update_message_history(messages, response, tool_results)

    _save_final_report(scan_data, backend_url)
    console.print("\n[cyan]AI scan complete.[/cyan]")


def build_report_from_findings(findings: List[str], recommendations: List[str], risk_level: str, scan_data: Dict[str, Any]) -> ScanReport:
    """Build a ScanReport from AI findings."""
    report = ScanReport(
        scan_id=generate_scan_id(),
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        network=scan_data.get("network", "Unknown"),
        scan_mode=scan_data.get("scan_mode", "quick"),
        total_devices=len(scan_data.get("devices", [])),
        overall_findings=findings,
        overall_recommendations=recommendations,
        overall_risk=risk_level,
    )
    for device_data in scan_data.get("devices", []):
        report.devices.append(_build_device_report(device_data))
    return report


def run_agent_interactive() -> None:
    """Run agent with config check/setup."""
    config = load_config()
    provider_info = "HomeGuard backend" if config.is_backend_proxy else f"{config.provider} / {config.model}"
    console.print(f"[dim]Using {provider_info}[/dim]\n")
    run_agent(config)
