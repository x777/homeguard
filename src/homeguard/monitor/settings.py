"""Monitoring settings management."""

import json
from pathlib import Path
from typing import Optional


class MonitorSettings:
    """Manage monitoring configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path.home() / ".homeguard" / "monitor_config.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings = self._load()
    
    def _load(self) -> dict:
        """Load settings from disk."""
        if self.config_path.exists():
            return json.loads(self.config_path.read_text())
        return self._defaults()
    
    def _defaults(self) -> dict:
        """Default settings."""
        return {
            "enabled": False,
            "interval_hours": 6,
            "alert_new_devices": True,
            "alert_vulnerabilities": True,
            "alert_config_changes": True,
            "alert_port_changes": True,
            "notification_desktop": True,
            "notification_telegram": False,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "notification_email": False,
            "email_address": "",
            "min_severity": "medium",  # low, medium, high, critical
        }
    
    def save(self):
        """Save settings to disk."""
        self.config_path.write_text(json.dumps(self.settings, indent=2))
    
    def get(self, key: str, default=None):
        """Get setting value."""
        return self.settings.get(key, default)
    
    def set(self, key: str, value):
        """Set setting value."""
        self.settings[key] = value
        self.save()
    
    def update(self, **kwargs):
        """Update multiple settings."""
        self.settings.update(kwargs)
        self.save()
