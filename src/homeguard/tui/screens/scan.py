"""Scan screen with real-time progress."""

import logging
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static
from textual.worker import get_current_worker

from homeguard.tui.widgets import DeviceTable, ScanLog

# File logging for debug
LOG_FILE = Path.home() / ".homeguard" / "tui_debug.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("homeguard.tui")


class ScanScreen(Screen):
    """Screen for active network scanning."""

    BINDINGS = [
        ("c", "cancel_scan", "Cancel"),
        ("escape", "go_back", "Back"),
        ("d", "go_back", "Done"),
    ]

    def __init__(self, full_scan: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.full_scan = full_scan
        self.scan_data: dict = {"devices": [], "device_map": {}}

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="scan-container"):
            mode = "AI Security Scan" if self.full_scan else "Quick Scan"
            yield Static(f"🔍 {mode}...", id="scan-status")
            with Vertical(id="progress-container"):
                yield ProgressBar(id="progress", show_eta=False)
            yield DeviceTable(id="scan-devices")
            yield ScanLog(id="scan-log")
        yield Footer()

    def on_mount(self) -> None:
        """Start scan on mount."""
        logger.info(f"ScanScreen mounted, full_scan={self.full_scan}")
        self.run_scan()

    @work(exclusive=True, thread=True)
    def run_scan(self) -> None:
        """Run the network scan in a worker thread."""
        logger.info("run_scan worker started")
        worker = get_current_worker()
        log = self.query_one(ScanLog)
        table = self.query_one(DeviceTable)
        progress = self.query_one(ProgressBar)
        status = self.query_one("#scan-status", Static)

        def ui(func, *args, **kwargs):
            self.app.call_from_thread(func, *args, **kwargs)

        try:
            from datetime import datetime
            from homeguard.agent.config import load_config
            from homeguard.agent.constants import DEFAULT_BACKEND_URL
            from homeguard.scanner.discovery import scan_network, get_local_ip, get_network_cidr
            from homeguard.scanner.ports import scan_ports
            from homeguard.agent.tools import identify_device_enhanced, get_mac_vendor
            from homeguard.agent.constants import DEFAULT_BACKEND_URL
            from homeguard.agent.report import ScanReport, DeviceReport, generate_scan_id, save_report
            from homeguard.agent.scan_orchestrator import ScanOrchestrator

            config = load_config()
            backend_url = config.base_url or DEFAULT_BACKEND_URL
            logger.info(f"Config loaded: scan_mode={config.scan_mode}, full_scan={self.full_scan}")

            orchestrator = ScanOrchestrator(backend_url)

            # === PHASE 1: Network Discovery ===
            ui(log.log_info, "Phase 1: Network Discovery")
            ui(status.update, "🔍 Phase 1: Discovering devices...")

            local_ip = get_local_ip()
            network = get_network_cidr(local_ip)
            logger.info(f"Scanning network: {network}")
            ui(log.log_info, f"Scanning {network}")

            result = scan_network(network=network, timeout=3)
            devices = result.devices
            logger.info(f"Discovery complete: {len(devices)} devices found")

            if worker.is_cancelled:
                return

            ui(log.log_info, f"Found {len(devices)} devices")
            
            # Calculate total steps
            steps = len(devices)  # discovery
            steps += len(devices)  # port scan
            if self.full_scan:
                steps += len(devices) * 3  # deep scan + security + threat intel
            ui(progress.update, total=steps, progress=0)

            # === PHASE 2: Device Processing ===
            device_map = {}
            for device in devices:
                if worker.is_cancelled:
                    return

                ip = device.ip
                mac = device.mac
                vendor = get_mac_vendor(mac)
                logger.debug(f"Processing device: {ip} ({vendor})")

                device_data = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "os_guess": device.os_guess or "Unknown",
                    "device_type": "Unknown",
                    "open_ports": [],
                    "risks": [],
                    "deep_scan": {},
                    "encryption_check": {},
                    "upnp_check": {},
                    "threat_intel": {},
                }

                ui(log.log_device_found, ip, vendor)
                ui(table.add_device, device_data)
                ui(progress.advance, 1)
                device_map[ip] = device_data

            # === PHASE 3: Port Scanning ===
            ui(log.log_info, "Phase 2: Port Scanning")
            ui(status.update, "🔓 Phase 2: Scanning ports...")

            for ip, device_data in device_map.items():
                if worker.is_cancelled:
                    return

                logger.debug(f"Port scanning: {ip}")
                ui(log.log_tool_call, "scan_ports", {"ip": ip})

                ports = scan_ports(ip, quick=(config.scan_mode == "quick"), timeout=1.0)
                device_data["open_ports"] = [{"port": p.port, "service": p.service} for p in ports]
                logger.debug(f"  Found {len(ports)} open ports on {ip}")

                # Identify device type with enhanced method
                port_numbers = [p.port for p in ports]
                banners = {p.port: p.banner for p in ports if p.banner}
                use_llm = self.full_scan  # Use LLM for AI scans
                backend_url = DEFAULT_BACKEND_URL if use_llm else None
                
                device_info = identify_device_enhanced(
                    ip, 
                    device_data["mac"], 
                    port_numbers, 
                    device_data["os_guess"],
                    hostname=device_data.get("hostname"),
                    banners=banners if banners else None,
                    use_llm=use_llm,
                    backend_url=backend_url
                )
                device_data["device_type"] = device_info.get("device_type", "Unknown")
                device_data["confidence"] = device_info.get("confidence", "low")
                if device_info.get("vendor") != "Unknown":
                    device_data["vendor"] = device_info["vendor"]

                # Fingerprint device (works in both quick and full scan)
                from homeguard.agent.tools import execute_tool
                fp_result = execute_tool("fingerprint_device", {"ip": ip, "action": "create", "device_data": device_data})
                if fp_result and fp_result.success:
                    device_data["fingerprint_id"] = fp_result.data.get("fingerprint_id")

                # Check for fixable vulnerabilities (ONLY in full scan mode)
                if self.full_scan:
                    fix_result = execute_tool("list_fixable_vulnerabilities", {"device_data": device_data})
                    if fix_result and fix_result.success:
                        vulns = fix_result.data.get("vulnerabilities", [])
                        if vulns:
                            device_data["fixable_vulnerabilities"] = vulns
                            ui(log.log_info, f"Found {len(vulns)} fixable issues on {ip}")

                self._update_table(ui, table, device_map)
                ui(progress.advance, 1)

            recommendations = []
            
            if self.full_scan:
                # === PHASE 4: Deep Scans ===
                ui(log.log_info, "Phase 3: Deep Scanning")
                ui(status.update, "🔬 Phase 3: Deep scanning devices...")

                for ip, device_data in device_map.items():
                    if worker.is_cancelled:
                        return

                    device_type = device_data["device_type"]
                    self._run_deep_scan(ip, device_type, device_data, ui, log)
                    self._update_table(ui, table, device_map)
                    ui(progress.advance, 1)

                # === PHASE 5: Security Checks ===
                ui(log.log_info, "Phase 4: Security Checks")
                ui(status.update, "🔐 Phase 4: Running security checks...")

                for ip, device_data in device_map.items():
                    if worker.is_cancelled:
                        return

                    if any(p.get("port") in [80, 443, 8080, 8443] for p in device_data["open_ports"]):
                        self._run_security_checks(ip, device_data, ui, log)
                    self._update_table(ui, table, device_map)
                    ui(progress.advance, 1)

                # === PHASE 6: Threat Intelligence ===
                ui(log.log_info, "Phase 5: Threat Intelligence")
                ui(status.update, "🛡️ Phase 5: Querying threat databases...")

                for ip, device_data in device_map.items():
                    if worker.is_cancelled:
                        return

                    self._run_threat_intel(ip, device_data, backend_url, ui, log)
                    self._update_table(ui, table, device_map)
                    ui(progress.advance, 1)

                # === PHASE 7: LLM Recommendations ===
                ui(log.log_info, "Phase 6: Generating AI Recommendations")
                ui(status.update, "🤖 Phase 6: AI analysis...")
                
                recommendations = self._get_llm_recommendations(device_map, backend_url, ui, log)

            # === Save Report ===
            ui(status.update, "💾 Saving report...")
            logger.info("Saving report...")

            report = ScanReport(
                scan_id=generate_scan_id(),
                scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                network=network,
                scan_mode="full" if self.full_scan else "quick",
                total_devices=len(device_map),
                overall_recommendations=recommendations,
            )

            for dd in device_map.values():
                report.devices.append(DeviceReport(
                    ip=dd["ip"],
                    mac=dd["mac"],
                    device_type=dd["device_type"],
                    vendor=dd["vendor"],
                    os_guess=dd["os_guess"],
                    open_ports=dd["open_ports"],
                    risks=dd.get("risks", []),
                    deep_scan=dd.get("deep_scan", {}),
                    encryption_check=dd.get("encryption_check", {}),
                    upnp_check=dd.get("upnp_check", {}),
                    threat_intel=dd.get("threat_intel", {}),
                ))

            save_report(report)
            logger.info(f"Report saved: {report.scan_id}")

            self.scan_data = {"devices": list(device_map.values())}
            ui(log.log_complete, len(device_map))
            
            mode = "AI scan" if self.full_scan else "Quick scan"
            ui(status.update, f"✅ {mode} complete! Found {len(device_map)} devices. Press 'd' for results.")

        except Exception as e:
            logger.exception(f"Scan error: {e}")
            ui(log.log_error, str(e))
            ui(status.update, f"❌ Error: {e}")

    def _update_table(self, ui, table, device_map):
        """Update the device table."""
        ui(table.clear_devices)
        for d in device_map.values():
            ui(table.add_device, d)

    def _run_deep_scan(self, ip: str, device_type: str, device_data: dict, ui, log):
        """Run appropriate deep scan based on device type."""
        from homeguard.agent.tools import execute_tool

        scan_map = {
            "Router": "deep_scan_router",
            "Gateway": "deep_scan_router",
            "IoT Device": "deep_scan_iot",
            "Smart TV": "deep_scan_iot",
            "IP Camera": "deep_scan_iot",
            "NAS": "deep_scan_storage",
            "Server": "deep_scan_storage",
        }

        tool_name = None
        for key, tool in scan_map.items():
            if key in device_type:
                tool_name = tool
                break

        if not tool_name and device_type == "Unknown Device":
            tool_name = "probe_unknown_device"

        if tool_name:
            ui(log.log_tool_call, tool_name, {"ip": ip})
            logger.debug(f"Deep scan {tool_name} on {ip}")
            
            args = {"ip": ip}
            if tool_name == "probe_unknown_device":
                args["known_ports"] = [p.get("port") for p in device_data["open_ports"]]
            
            result = execute_tool(tool_name, args)
            if result and result.success:
                device_data["deep_scan"] = result.data
                
                # Check for findings
                findings = result.data.get("findings", [])
                for f in findings:
                    if isinstance(f, dict) and f.get("note"):
                        ui(log.log_finding, f"{ip}: {f['note'][:50]}", "medium")

    def _run_security_checks(self, ip: str, device_data: dict, ui, log):
        """Run security checks on device."""
        from homeguard.agent.tools import execute_tool

        # Encryption check
        ui(log.log_tool_call, "check_encryption", {"ip": ip})
        result = execute_tool("check_encryption", {"ip": ip})
        if result and result.success:
            device_data["encryption_check"] = result.data
            for f in result.data.get("findings", []):
                if "weak" in f.lower() or "http" in f.lower():
                    ui(log.log_finding, f"{ip}: {f[:50]}", "high")

        # UPnP check
        ui(log.log_tool_call, "check_upnp_exposure", {"ip": ip})
        result = execute_tool("check_upnp_exposure", {"ip": ip})
        if result and result.success:
            device_data["upnp_check"] = result.data
            if result.data.get("upnp_found"):
                ui(log.log_finding, f"{ip}: UPnP enabled", "medium")

    def _run_threat_intel(self, ip: str, device_data: dict, backend_url: str, ui, log):
        """Query threat intelligence for device."""
        from homeguard.agent.tools import execute_tool

        vendor = device_data.get("vendor", "Unknown")
        if vendor and vendor != "Unknown":
            # Normalize vendor name
            vendor_lower = vendor.lower()
            normalized = vendor_lower.split()[0]
            for pattern, norm in [("xiaomi", "xiaomi"), ("tp-link", "tp-link"), ("asus", "asus")]:
                if pattern in vendor_lower:
                    normalized = norm
                    break

            ui(log.log_tool_call, "check_threat_intel", {"vendor": normalized})
            logger.debug(f"Threat intel for {ip}: {normalized}")
            
            result = execute_tool("check_threat_intel", {"vendor": normalized}, backend_url=backend_url)
            if result and result.success:
                device_data["threat_intel"] = result.data
                
                # Log CVEs found
                cves = result.data.get("advisories", []) + result.data.get("vulnerabilities", [])
                if cves:
                    critical = sum(1 for c in cves if c.get("severity", "").lower() == "critical")
                    high = sum(1 for c in cves if c.get("severity", "").lower() == "high")
                    if critical:
                        ui(log.log_finding, f"{ip}: {critical} CRITICAL CVEs found!", "critical")
                    elif high:
                        ui(log.log_finding, f"{ip}: {high} HIGH severity CVEs", "high")

    def _get_llm_recommendations(self, device_map: dict, backend_url: str, ui, log) -> list:
        """Get LLM-generated recommendations."""
        import httpx

        # Build summary for LLM
        summary_lines = ["Network scan summary:"]
        for ip, d in device_map.items():
            line = f"- {ip}: {d['device_type']} ({d['vendor']})"
            ports = [p.get("port") for p in d["open_ports"]]
            if ports:
                line += f", ports: {ports}"
            threat = d.get("threat_intel", {})
            cves = threat.get("advisories", []) + threat.get("vulnerabilities", [])
            if cves:
                line += f", {len(cves)} CVEs"
            summary_lines.append(line)

        prompt = "\n".join(summary_lines) + "\n\nYou are a cybersecurity consultant. Based on this network scan summary, provide exactly 5 specific, prioritized security recommendations. Use priority indicators: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW. Be device-specific with IP addresses. Respond with plain text recommendations, one per line."
        try:
            ui(log.log_info, "Requesting AI recommendations...")
            logger.info(f"LLM request to {backend_url}/api/chat")
            response = httpx.post(
                f"{backend_url}/api/chat",
                json={"messages": [{"role": "user", "content": prompt}]},
                timeout=30.0,
            )
            logger.info(f"LLM response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                # Handle both response formats
                content = data.get("content") or data.get("message", {}).get("content", "")
                logger.debug(f"LLM content: {content[:200]}")
                # Parse recommendations
                recs = []
                for line in content.split("\n"):
                    line = line.strip()
                    # Match lines starting with emoji, number, dash, or asterisk
                    if line and (line[0].isdigit() or line.startswith("-") or line.startswith("*") or 
                                 line.startswith("🔴") or line.startswith("🟠") or 
                                 line.startswith("🟡") or line.startswith("🟢")):
                        # Clean up numbering/bullets but keep emojis
                        clean = line.lstrip("0123456789.-)*• ")
                        if clean:
                            recs.append(clean)
                if recs:
                    logger.info(f"Generated {len(recs)} recommendations")
                    ui(log.log_info, f"✨ AI generated {len(recs)} recommendations:")
                    for i, rec in enumerate(recs[:5], 1):
                        ui(log.write, f"  [bold cyan]{i}.[/bold cyan] {rec}")
                    return recs[:5]
            else:
                logger.warning(f"LLM error: {response.status_code} - {response.text[:100]}")
                ui(log.log_info, f"AI unavailable (status {response.status_code})")
        except Exception as e:
            logger.warning(f"LLM recommendations failed: {e}")
            ui(log.log_info, f"AI recommendations unavailable: {e}")

        return []

    def action_cancel_scan(self) -> None:
        """Cancel the scan and return to main screen."""
        self.workers.cancel_all()
        self._go_to_main()

    def action_go_back(self) -> None:
        """Go back to main screen with results."""
        self._go_to_main()

    def _go_to_main(self) -> None:
        """Return to main screen, loading results if available."""
        main = self.app.get_screen("main")
        if self.scan_data.get("devices"):
            main.load_scan_result(self.scan_data["devices"])
        self.app.pop_screen()
