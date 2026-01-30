# Network Monitoring Feature

## Overview
Continuous network monitoring with automated change detection and alerting. Runs background scans at configurable intervals and notifies you of security changes.

## Features

### 🔍 Automated Scanning
- Schedule periodic scans (1-24 hour intervals)
- Runs in background without user interaction
- Lightweight quick scans for continuous monitoring

### 🔔 Smart Alerts
Detects and alerts on:
- **New Devices**: Unknown devices joining network
- **Device Removal**: Known devices going offline
- **Port Changes**: Services starting/stopping
- **Vulnerabilities**: New CVEs affecting your devices
- **Config Changes**: Security settings modified

### ⚙️ Configurable Settings
- Enable/disable monitoring
- Scan interval (1-24 hours)
- Alert type filters
- Severity threshold (low/medium/high/critical)
- Notification preferences

### 📬 Notifications
- Desktop notifications (macOS)
- Alert history (last 100 alerts)
- Severity-based filtering

## Usage

### TUI Interface

**Access Monitoring Dashboard:**
```
Press 'm' from main screen
```

**Monitoring Screen Actions:**
- `r` - Run scan immediately
- `c` - Clear all alerts
- `s` - Open settings
- `Esc` - Back to main screen

**Settings Screen:**
- Configure scan interval
- Enable/disable alert types
- Set notification preferences
- Save or cancel changes

### Programmatic Usage

```python
from homeguard.monitor import NetworkMonitor
from homeguard.monitor.settings import MonitorSettings

# Configure settings
settings = MonitorSettings()
settings.update(
    enabled=True,
    interval_hours=6,
    alert_new_devices=True,
    notification_desktop=True
)

# Start monitoring
monitor = NetworkMonitor()
monitor.start()

# Run immediate scan
alerts = monitor.run_now()

# Get recent alerts
recent = monitor.get_alerts(limit=10)

# Stop monitoring
monitor.stop()
```

## Architecture

### Components

**NetworkMonitor** (`scheduler.py`)
- Background scheduler using APScheduler
- Scan orchestration
- Change detection logic
- Alert generation

**MonitorSettings** (`settings.py`)
- Configuration management
- Persistent storage (~/.homeguard/monitor_config.json)
- Default values

**Alert** (`alerts.py`)
- Alert data model
- Alert types enum
- Severity levels

### Data Storage

```
~/.homeguard/
├── monitor_config.json    # Settings
├── alerts.json            # Alert history (last 100)
└── reports/               # Scan baselines
```

### Change Detection Algorithm

1. Load baseline (most recent scan)
2. Run new scan
3. Compare device lists:
   - New IPs → NEW_DEVICE alert
   - Missing IPs → DEVICE_REMOVED alert
4. Compare port lists per device:
   - New ports → PORT_OPENED alert
   - Missing ports → PORT_CLOSED alert
5. Filter by severity threshold
6. Save alerts and send notifications
7. Update baseline

## UI/UX Design

### Monitoring Screen
```
┌─────────────────────────────────────────────────────┐
│ 📊 Network Monitoring                               │
├─────────────────────────────────────────────────────┤
│ Status: ● Active                                    │
│ Scan Interval: Every 6 hours                        │
│                                                     │
│ 🔔 Recent Alerts                                    │
│  🟠 New device detected: 192.168.0.145              │
│     Device type: Unknown (12:34)                    │
│  🟡 Port 80 opened on 192.168.0.1                   │
│     New service detected (12:30)                    │
│                                                     │
│ [Run Scan Now] [Clear Alerts] [Settings]           │
└─────────────────────────────────────────────────────┘
```

### Settings Screen
```
┌─────────────────────────────────────────────────────┐
│ ⚙️ Monitoring Settings                              │
├─────────────────────────────────────────────────────┤
│ Enable Monitoring:        [✓]                       │
│ Scan Interval:            [6 hours ▼]               │
│                                                     │
│ 🔔 Alert Types                                      │
│ New Devices:              [✓]                       │
│ Vulnerabilities:          [✓]                       │
│ Config Changes:           [✓]                       │
│ Port Changes:             [✓]                       │
│                                                     │
│ 📬 Notifications                                    │
│ Desktop Notifications:    [✓]                       │
│ Minimum Severity:         [Medium ▼]                │
│                                                     │
│ [Save] [Cancel]                                     │
└─────────────────────────────────────────────────────┘
```

## Implementation Details

### Minimal Code Approach
- **Total Lines**: ~600 lines across 6 files
- **Dependencies**: Only `apscheduler` added
- **Reuse**: 90% leverages existing scan infrastructure

### Files Created
```
src/homeguard/monitor/
├── __init__.py           (5 lines)
├── alerts.py            (35 lines)
├── settings.py          (55 lines)
└── scheduler.py         (200 lines)

src/homeguard/tui/screens/
├── monitoring.py        (130 lines)
└── settings.py          (120 lines)
```

### Integration Points
- `HomeGuardApp.__init__()` - Initialize and start monitor
- `HomeGuardApp.action_quit()` - Stop monitor on exit
- `MainScreen` - Add 'm' keybinding
- `styles.tcss` - Add screen styles

## Future Enhancements

### Phase 2 (Optional)
- Email notifications
- Webhook integration (Slack, Discord)
- Trend analysis graphs
- Export alert reports
- Custom alert rules
- Multi-network support

### Phase 3 (Advanced)
- Machine learning anomaly detection
- Predictive vulnerability alerts
- Automated remediation triggers
- Mobile app notifications
- Cloud sync for multi-location monitoring

## Testing

```bash
# Install dependency
pip install apscheduler

# Run demo
python scripts/demo_monitoring.py

# Test in TUI
homeguard
# Press 'm' for monitoring
# Press 's' for settings
```

## Security Considerations

- Monitoring runs with same permissions as main app
- No external network connections (except scan targets)
- Settings stored locally (no cloud sync)
- Alert history limited to 100 entries
- No sensitive data in alerts (IPs only)

## Performance

- Background scheduler: ~5MB RAM
- Scan overhead: Same as manual quick scan
- Alert storage: <100KB
- CPU usage: Minimal (only during scans)

## Troubleshooting

**Monitoring not starting:**
- Check settings: `enabled` must be `true`
- Verify permissions for background process

**No alerts generated:**
- First scan creates baseline (no alerts)
- Check severity threshold in settings
- Verify alert types are enabled

**Desktop notifications not working:**
- macOS only (uses `osascript`)
- Check System Preferences → Notifications
- Terminal must have notification permissions
