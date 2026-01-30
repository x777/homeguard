"""Report generation and storage."""

import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

REPORTS_DIR = Path.home() / ".homeguard" / "reports"


@dataclass
class DeviceReport:
    ip: str
    mac: str
    device_type: str
    vendor: str
    os_guess: str
    model: str = ""
    firmware_version: str = ""
    open_ports: list[dict] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    deep_scan: dict = field(default_factory=dict)
    encryption_check: dict = field(default_factory=dict)
    firmware_check: dict = field(default_factory=dict)
    upnp_check: dict = field(default_factory=dict)
    dns_check: dict = field(default_factory=dict)
    threat_intel: dict = field(default_factory=dict)
    llm_identification: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    scan_id: str
    scan_time: str
    network: str
    scan_mode: str
    total_devices: int
    risk_summary: dict = field(default_factory=dict)
    devices: list[DeviceReport] = field(default_factory=list)
    overall_findings: list[str] = field(default_factory=list)
    overall_recommendations: list[str] = field(default_factory=list)
    overall_risk: str = "low"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "scan_time": self.scan_time,
            "network": self.network,
            "scan_mode": self.scan_mode,
            "total_devices": self.total_devices,
            "risk_summary": self.risk_summary,
            "overall_risk": self.overall_risk,
            "overall_findings": self.overall_findings,
            "overall_recommendations": self.overall_recommendations,
            "devices": [asdict(d) for d in self.devices],
        }


def generate_scan_id() -> str:
    """Generate unique scan ID."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_report(report: ScanReport) -> Path:
    """Save report to JSON file."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = REPORTS_DIR / f"scan_{report.scan_id}.json"
    with open(filepath, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    return filepath


def load_report(scan_id: str) -> Optional[ScanReport]:
    """Load report from file."""
    filepath = REPORTS_DIR / f"scan_{scan_id}.json"
    if not filepath.exists():
        return None
    with open(filepath) as f:
        data = json.load(f)
    devices = [DeviceReport(**d) for d in data.get("devices", [])]
    return ScanReport(
        scan_id=data["scan_id"],
        scan_time=data["scan_time"],
        network=data["network"],
        scan_mode=data.get("scan_mode", "quick"),
        total_devices=data["total_devices"],
        risk_summary=data.get("risk_summary", {}),
        devices=devices,
        overall_findings=data.get("overall_findings", []),
        overall_recommendations=data.get("overall_recommendations", []),
        overall_risk=data.get("overall_risk", "low"),
    )


def list_reports() -> list[dict]:
    """List all saved reports."""
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True):
        try:
            with open(f) as file:
                data = json.load(file)
                reports.append({
                    "scan_id": data["scan_id"],
                    "scan_time": data["scan_time"],
                    "network": data["network"],
                    "total_devices": data["total_devices"],
                    "overall_risk": data.get("overall_risk", "unknown"),
                    "scan_mode": data.get("scan_mode", "quick"),
                })
        except Exception:
            pass
    return reports


def format_cli_report(report: ScanReport) -> str:
    """Format report for CLI display - consistent template."""
    lines = []
    lines.append("=" * 60)
    lines.append("🛡️  HOMEGUARD SECURITY REPORT")
    lines.append("=" * 60)
    lines.append(f"Scan ID:      {report.scan_id}")
    lines.append(f"Time:         {report.scan_time}")
    lines.append(f"Network:      {report.network}")
    lines.append(f"Scan Mode:    {report.scan_mode}")
    lines.append(f"Devices:      {report.total_devices}")
    lines.append("")
    
    # Risk Summary
    risk_colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    lines.append(f"Overall Risk: {risk_colors.get(report.overall_risk, '⚪')} {report.overall_risk.upper()}")
    lines.append("")
    
    # Device Summary
    lines.append("-" * 60)
    lines.append("DEVICES FOUND")
    lines.append("-" * 60)
    for i, device in enumerate(report.devices, 1):
        lines.append(f"\n[{i}] {device.ip} - {device.device_type}")
        lines.append(f"    MAC: {device.mac}")
        lines.append(f"    Vendor: {device.vendor}")
        if device.model:
            lines.append(f"    Model: {device.model}")
        if device.firmware_version:
            lines.append(f"    Firmware: {device.firmware_version}")
        lines.append(f"    OS: {device.os_guess}")
        if device.open_ports:
            ports_str = ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in device.open_ports)
            lines.append(f"    Ports: {ports_str}")
        if device.risks:
            for risk in device.risks:
                lines.append(f"    ⚠️  {risk}")
        # Show deep scan findings
        if device.deep_scan:
            if device.deep_scan.get("findings"):
                for finding in device.deep_scan["findings"]:
                    if isinstance(finding, dict):
                        if finding.get("note"):
                            lines.append(f"    → {finding.get('service', 'Check')}: {finding['note']}")
                        elif finding.get("status"):
                            lines.append(f"    → {finding['status']}")
                    elif isinstance(finding, str):
                        lines.append(f"    → {finding}")
        # Show encryption check findings
        if device.encryption_check and device.encryption_check.get("findings"):
            for finding in device.encryption_check["findings"]:
                lines.append(f"    🔐 {finding}")
        # Show firmware check findings
        if device.firmware_check and device.firmware_check.get("findings"):
            for finding in device.firmware_check["findings"]:
                lines.append(f"    📦 {finding}")
        # Show UPnP check findings
        if device.upnp_check and device.upnp_check.get("findings"):
            for finding in device.upnp_check["findings"]:
                lines.append(f"    🔌 {finding}")
        # Show DNS hijacking check findings
        if device.dns_check and device.dns_check.get("findings"):
            for finding in device.dns_check["findings"]:
                lines.append(f"    🌐 {finding}")
        # Show threat intel findings
        if device.threat_intel:
            if device.threat_intel.get("advisories"):
                for adv in device.threat_intel["advisories"][:3]:
                    sev = adv.get('severity', 'Unknown')
                    cve = adv.get('cve_id', 'Unknown')
                    desc = adv.get('description', '')[:55]
                    lines.append(f"    ⚠️ {sev}: {cve} - {desc}...")
            if device.threat_intel.get("vulnerabilities"):
                for vuln in device.threat_intel["vulnerabilities"][:3]:
                    lines.append(f"    ⚠️ CVE: {vuln.get('id', 'Unknown')} - {vuln.get('description', '')[:55]}...")
            if device.threat_intel.get("iot_exploits"):
                for exp in device.threat_intel["iot_exploits"][:3]:
                    lines.append(f"    🎯 IoT: {exp.get('title', exp.get('name', 'Unknown'))[:60]}")
        # Show LLM identification
        if device.llm_identification:
            llm_id = device.llm_identification
            if llm_id.get("reasoning"):
                lines.append(f"    🤖 AI: {llm_id['reasoning'][:80]}")
            if llm_id.get("security_tips"):
                for tip in llm_id["security_tips"][:2]:
                    lines.append(f"    💡 {tip[:70]}")
        
        # Show fixable vulnerabilities (NEW)
        if hasattr(device, 'fixable_vulnerabilities') and device.fixable_vulnerabilities:
            lines.append(f"    🔧 FIXABLE ISSUES:")
            for vuln in device.fixable_vulnerabilities[:3]:
                severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(vuln.get("severity"), "⚪")
                lines.append(f"      {severity_icon} {vuln.get('description', 'Unknown')}")
            if len(device.fixable_vulnerabilities) > 3:
                lines.append(f"      ... and {len(device.fixable_vulnerabilities) - 3} more")
        
        # Show fingerprint match (NEW)
        if hasattr(device, 'fingerprint_match') and device.fingerprint_match:
            match_info = device.fingerprint_match
            lines.append(f"    🔍 Device: {match_info['type']} match ({match_info['confidence']:.0%})")
    
    # Findings
    if report.overall_findings:
        lines.append("")
        lines.append("-" * 60)
        lines.append("FINDINGS")
        lines.append("-" * 60)
        for i, finding in enumerate(report.overall_findings, 1):
            lines.append(f"  {i}. {finding}")
    
    # Recommendations
    if report.overall_recommendations:
        lines.append("")
        lines.append("-" * 60)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 60)
        for i, rec in enumerate(report.overall_recommendations, 1):
            lines.append(f"  {i}. {rec}")
    
    # Deep scan recommendations (deduplicated)
    deep_recs = set()
    for device in report.devices:
        if device.deep_scan and device.deep_scan.get("recommendations"):
            for rec in device.deep_scan["recommendations"]:
                deep_recs.add(rec)
    
    if deep_recs:
        if not report.overall_recommendations:
            lines.append("")
            lines.append("-" * 60)
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 60)
        start_num = len(report.overall_recommendations) + 1
        for i, rec in enumerate(sorted(deep_recs), start_num):
            lines.append(f"  {i}. {rec}")
    
    lines.append("")
    lines.append("=" * 60)
    lines.append(f"Report saved: ~/.homeguard/reports/scan_{report.scan_id}.json")
    lines.append("=" * 60)
    
    return "\n".join(lines)
