"""Network monitoring scheduler."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from apscheduler.schedulers.background import BackgroundScheduler

from homeguard.agent.report import load_report, save_report, list_reports
from homeguard.agent.config import load_config
from .alerts import Alert, AlertType
from .settings import MonitorSettings

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Background network monitoring with change detection."""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.settings = MonitorSettings()
        self.alerts_path = Path.home() / ".homeguard" / "alerts.json"
        self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_report = None
        self._load_baseline()
    
    def _load_baseline(self):
        """Load most recent report as baseline."""
        reports = list_reports()
        if reports:
            latest = reports[0]
            report_obj = load_report(latest["scan_id"])
            # Convert ScanReport to dict for comparison
            self.baseline_report = report_obj.to_dict() if hasattr(report_obj, 'to_dict') else report_obj
    
    def start(self):
        """Start monitoring scheduler."""
        if not self.settings.get("enabled"):
            return
        
        interval = self.settings.get("interval_hours", 6)
        self.scheduler.add_job(
            self._scan_and_compare,
            'interval',
            hours=interval,
            id='network_scan',
            replace_existing=True
        )
        self.scheduler.start()
        logger.info(f"Monitoring started (interval: {interval}h)")
    
    def stop(self):
        """Stop monitoring scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Monitoring stopped")
    
    def run_now(self) -> List[Alert]:
        """Run scan immediately and return alerts."""
        return self._scan_and_compare()
    
    def _scan_and_compare(self) -> List[Alert]:
        """Run scan and detect changes."""
        logger.info("Running scheduled scan...")
        
        try:
            # Run quick scan using scanner directly
            from homeguard.scanner.discovery import scan_network
            from homeguard.scanner.ports import scan_ports
            
            # Network discovery
            scan_result = scan_network()
            devices = scan_result.devices
            
            # Port scanning (quick mode)
            for device in devices:
                port_results = scan_ports(device.ip, quick=True)
                device.open_ports = port_results
            
            # Create report
            current_report = {
                "scan_id": f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "scan_time": datetime.now().isoformat(),
                "scan_mode": "monitor",
                "devices": [d.to_dict() for d in devices],
            }
            
            # Detect changes
            alerts = []
            if self.baseline_report:
                alerts = self._detect_changes(self.baseline_report, current_report)
            else:
                # First scan - create info alert
                alerts.append(Alert(
                    type=AlertType.NEW_DEVICE,
                    severity="low",
                    title=f"Baseline created: {len(devices)} devices found",
                    description="First scan complete. Future scans will detect changes.",
                    device_ip=None
                ))
            
            # Save as new baseline
            self.baseline_report = current_report
            
            # Store alerts
            if alerts:
                self._save_alerts(alerts)
                self._send_notifications(alerts)
            
            logger.info(f"Scan complete. {len(alerts)} alerts generated.")
            return alerts
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return []
    
    def _detect_changes(self, baseline: dict, current: dict) -> List[Alert]:
        """Compare scans and generate alerts."""
        alerts = []
        
        baseline_ips = {d.get("ip") for d in baseline.get("devices", [])}
        current_ips = {d.get("ip") for d in current.get("devices", [])}
        
        # New devices
        if self.settings.get("alert_new_devices"):
            for ip in current_ips - baseline_ips:
                device = next((d for d in current["devices"] if d.get("ip") == ip), {})
                alerts.append(Alert(
                    type=AlertType.NEW_DEVICE,
                    severity="high",
                    title=f"New device detected: {ip}",
                    description=f"Device type: {device.get('device_type', 'Unknown')}",
                    device_ip=ip
                ))
        
        # Removed devices
        for ip in baseline_ips - current_ips:
            alerts.append(Alert(
                type=AlertType.DEVICE_REMOVED,
                severity="low",
                title=f"Device offline: {ip}",
                description="Device no longer responding",
                device_ip=ip
            ))
        
        # Port changes
        if self.settings.get("alert_port_changes"):
            for ip in baseline_ips & current_ips:
                baseline_dev = next((d for d in baseline["devices"] if d.get("ip") == ip), {})
                current_dev = next((d for d in current["devices"] if d.get("ip") == ip), {})
                
                baseline_ports = {p.get("port") for p in baseline_dev.get("open_ports", [])}
                current_ports = {p.get("port") for p in current_dev.get("open_ports", [])}
                
                # New open ports
                for port in current_ports - baseline_ports:
                    alerts.append(Alert(
                        type=AlertType.PORT_OPENED,
                        severity="medium",
                        title=f"Port {port} opened on {ip}",
                        description=f"New service detected",
                        device_ip=ip
                    ))
        
        # Filter by severity
        min_severity = self.settings.get("min_severity", "medium")
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 1)
        
        return [a for a in alerts if severity_order.get(a.severity, 0) >= min_level]
    
    def _save_alerts(self, alerts: List[Alert]):
        """Save alerts to disk."""
        existing = []
        if self.alerts_path.exists():
            existing = json.loads(self.alerts_path.read_text())
        
        existing.extend([a.to_dict() for a in alerts])
        
        # Keep last 100 alerts
        existing = existing[-100:]
        
        self.alerts_path.write_text(json.dumps(existing, indent=2))
    
    def get_alerts(self, limit: int = 20) -> List[dict]:
        """Get recent alerts."""
        if not self.alerts_path.exists():
            return []
        
        alerts = json.loads(self.alerts_path.read_text())
        return alerts[-limit:][::-1]  # Most recent first
    
    def clear_alerts(self):
        """Clear all alerts."""
        if self.alerts_path.exists():
            self.alerts_path.write_text("[]")
    
    def _send_notifications(self, alerts: List[Alert]):
        """Send notifications for alerts."""
        # Desktop notifications (macOS)
        if self.settings.get("notification_desktop"):
            try:
                import subprocess
                for alert in alerts[:3]:  # Limit to 3 notifications
                    title = f"HomeGuard: {alert.title}"
                    subprocess.run([
                        "osascript", "-e",
                        f'display notification "{alert.description}" with title "{title}"'
                    ], check=False)
            except Exception as e:
                logger.error(f"Desktop notification failed: {e}")
        
        # Telegram notifications
        if self.settings.get("notification_telegram"):
            bot_token = self.settings.get("telegram_bot_token")
            chat_id = self.settings.get("telegram_chat_id")
            if bot_token and chat_id:
                self._send_telegram(alerts, bot_token, chat_id)
    
    def _send_telegram(self, alerts: List[Alert], bot_token: str, chat_id: str):
        """Send Telegram notifications."""
        try:
            import requests
            
            # Group alerts by severity
            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            
            message = "🛡️ *HomeGuard Alert*\n\n"
            for alert in alerts[:5]:  # Limit to 5 alerts
                icon = severity_icons.get(alert.severity, "⚪")
                message += f"{icon} *{alert.title}*\n"
                message += f"   {alert.description}\n\n"
            
            if len(alerts) > 5:
                message += f"_...and {len(alerts) - 5} more alerts_"
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            requests.post(url, json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }, timeout=5)
            
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")
