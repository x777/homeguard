# Feature: Textual TUI Dashboard

The following plan should be complete, but validate documentation and codebase patterns before implementing.

Pay special attention to naming of existing utils, types, and models. Import from the right files.

## Feature Description

Replace the current questionary-based interactive menu with a modern Textual TUI dashboard. The dashboard provides real-time scan progress, interactive device browsing, and a rich findings explorer - all with keyboard shortcuts and mouse support.

## User Story

As a security-conscious home user
I want an interactive dashboard to monitor network scans
So that I can easily browse devices, view findings, and understand my network security posture

## Problem Statement

Current UI limitations:
- No real-time progress during scans (just a spinner)
- Static text output - can't drill into device details
- No scan history browser in UI (reports ARE saved to `~/.homeguard/reports/`, `list_reports()` and `load_report()` exist in `report.py` but not exposed in interactive menu)
- Must wait for full scan to complete before seeing any results
- No keyboard shortcuts for power users

**Note**: Scan history storage already works! Reports are saved as JSON files. The TUI just needs to call existing `list_reports()` and `load_report(scan_id)` functions from `report.py`.

## Solution Statement

Build a Textual-based TUI with:
1. Real-time device discovery table (updates as devices are found)
2. Interactive device details panel (click/select to view)
3. Findings tree with expand/collapse
4. Scan history sidebar
5. Keyboard shortcuts for all actions

## Feature Metadata

**Feature Type**: Enhancement
**Estimated Complexity**: High
**Primary Systems Affected**: `interactive.py`, `loop.py`, `report.py`
**Dependencies**: `textual>=0.40.0`

---

## CONTEXT REFERENCES

### Relevant Codebase Files - READ BEFORE IMPLEMENTING

- `src/homeguard/interactive.py` (full file) - Why: Current menu implementation to replace
- `src/homeguard/agent/loop.py` (lines 1-80) - Why: Agent loop UI helpers to integrate with
- `src/homeguard/agent/loop.py` (lines 380-420) - Why: `run_agent` function signature
- `src/homeguard/agent/report.py` (lines 1-70) - Why: `DeviceReport`, `ScanReport` dataclasses
- `src/homeguard/agent/report.py` (lines 95-120) - Why: `list_reports()`, `load_report()` - ALREADY IMPLEMENTED, just need to call these
- `src/homeguard/cli.py` (lines 155-165) - Why: Entry point that calls `run_interactive()`

### New Files to Create

```
src/homeguard/tui/
├── __init__.py          # Package exports
├── app.py               # Main HomeGuardApp class
├── screens/
│   ├── __init__.py
│   ├── main.py          # MainScreen with dashboard layout
│   └── scan.py          # ScanScreen for active scanning
├── widgets/
│   ├── __init__.py
│   ├── device_table.py  # DeviceTable widget
│   ├── device_panel.py  # DeviceDetails panel
│   ├── findings_tree.py # FindingsTree widget
│   └── scan_log.py      # ScanLog for real-time output
└── styles.tcss          # CSS styling
```

### Relevant Documentation - READ BEFORE IMPLEMENTING

- [Textual Getting Started](https://textual.textualize.io/getting_started/)
  - Installation and basic app structure
  - Why: Foundation for app setup
- [Textual Workers Guide](https://textual.textualize.io/guide/workers/)
  - `@work` decorator, `thread=True`, `exclusive=True`
  - Why: Network scanning is blocking, needs workers
- [DataTable Widget](https://textual.textualize.io/widgets/data_table/)
  - Sortable, selectable rows
  - Why: Device list implementation
- [Tree Widget](https://textual.textualize.io/widgets/tree/)
  - Expandable nodes
  - Why: Findings hierarchy
- [TabbedContent Widget](https://textual.textualize.io/widgets/tabbed_content/)
  - Tab switching
  - Why: Report sections
- [Screens Guide](https://textual.textualize.io/guide/screens/)
  - Screen switching, push/pop
  - Why: Main vs Scan screen

### Patterns to Follow

**App Structure** (from Textual docs):
```python
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable

class HomeGuardApp(App):
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan", "New Scan"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable()
        yield Footer()
```

**Worker Pattern** (for blocking operations):
```python
from textual import work

class ScanScreen(Screen):
    @work(exclusive=True, thread=True)
    def run_scan(self) -> None:
        # Blocking network scan
        worker = get_current_worker()
        for device in scan_network():
            if worker.is_cancelled:
                return
            self.call_from_thread(self.add_device, device)
```

**Message Pattern** (for widget communication):
```python
from textual.message import Message

class DeviceTable(DataTable):
    class DeviceSelected(Message):
        def __init__(self, device: dict):
            self.device = device
            super().__init__()
    
    def on_data_table_row_selected(self, event):
        self.post_message(self.DeviceSelected(self.devices[event.row_key]))
```

**Naming Conventions** (from codebase):
- snake_case for functions/variables
- PascalCase for classes
- Type hints on all functions
- 100 char line length

---

## IMPLEMENTATION PLAN

### Phase 1: Foundation (Setup & Base App)

Set up Textual dependency and create base app structure.

**Tasks:**
- Add textual to dependencies
- Create tui package structure
- Create base HomeGuardApp with Header/Footer
- Create styles.tcss with theme

### Phase 2: Core Widgets

Build reusable widgets for device display and findings.

**Tasks:**
- DeviceTable: DataTable subclass with device columns
- DevicePanel: Static widget showing selected device details
- FindingsTree: Tree widget for security findings
- ScanLog: RichLog for real-time scan output

### Phase 3: Screens

Create main dashboard and scan screens.

**Tasks:**
- MainScreen: Dashboard with device table, details panel, history
- ScanScreen: Active scan view with progress and live device list

### Phase 4: Integration

Connect TUI to existing agent loop and report system.

**Tasks:**
- Modify agent loop to emit events instead of printing
- Wire up scan history from report.py
- Update cli.py entry point

---

## STEP-BY-STEP TASKS

### Task 1: UPDATE pyproject.toml

- **IMPLEMENT**: Add `textual>=0.40.0` to dependencies
- **VALIDATE**: `pip install -e . && python -c "import textual; print(textual.__version__)"`

### Task 2: CREATE src/homeguard/tui/__init__.py

- **IMPLEMENT**: Package init with exports
```python
from .app import HomeGuardApp

__all__ = ["HomeGuardApp"]
```
- **VALIDATE**: `python -c "from homeguard.tui import HomeGuardApp"`

### Task 3: CREATE src/homeguard/tui/styles.tcss

- **IMPLEMENT**: CSS styling for dashboard
```css
Screen {
    background: $surface;
}

Header {
    dock: top;
}

Footer {
    dock: bottom;
}

#device-table {
    height: 40%;
    border: solid $primary;
}

#device-panel {
    height: 60%;
    border: solid $secondary;
}

#scan-log {
    height: 100%;
    border: solid $primary;
}

.risk-critical { color: red; }
.risk-high { color: orange; }
.risk-medium { color: yellow; }
.risk-low { color: green; }
```
- **VALIDATE**: File exists and is valid CSS

### Task 4: CREATE src/homeguard/tui/widgets/__init__.py

- **IMPLEMENT**: Widget exports
- **VALIDATE**: `python -c "from homeguard.tui.widgets import DeviceTable"`

### Task 5: CREATE src/homeguard/tui/widgets/device_table.py

- **IMPLEMENT**: DataTable subclass for devices
- **PATTERN**: Follow DataTable docs pattern
- **IMPORTS**: `from textual.widgets import DataTable`
- **FEATURES**:
  - Columns: IP, Type, Vendor, Risk, Ports
  - Row selection emits DeviceSelected message
  - Risk column colored by level
  - Method: `add_device(device: dict)`
  - Method: `clear_devices()`
- **VALIDATE**: `python -c "from homeguard.tui.widgets.device_table import DeviceTable"`

### Task 6: CREATE src/homeguard/tui/widgets/device_panel.py

- **IMPLEMENT**: Static widget showing device details
- **IMPORTS**: `from textual.widgets import Static`
- **FEATURES**:
  - Display: IP, MAC, Vendor, Type, OS, Model
  - Display: Open ports with services
  - Display: Security findings list
  - Display: Threat intel (CVEs)
  - Method: `show_device(device: DeviceReport)`
- **VALIDATE**: `python -c "from homeguard.tui.widgets.device_panel import DevicePanel"`

### Task 7: CREATE src/homeguard/tui/widgets/findings_tree.py

- **IMPLEMENT**: Tree widget for findings hierarchy
- **IMPORTS**: `from textual.widgets import Tree`
- **FEATURES**:
  - Root nodes: Critical, High, Medium, Low
  - Child nodes: Individual findings
  - Expand/collapse by risk level
  - Method: `load_findings(devices: list[DeviceReport])`
- **VALIDATE**: `python -c "from homeguard.tui.widgets.findings_tree import FindingsTree"`

### Task 8: CREATE src/homeguard/tui/widgets/scan_log.py

- **IMPLEMENT**: RichLog for real-time scan output
- **IMPORTS**: `from textual.widgets import RichLog`
- **FEATURES**:
  - Auto-scroll to bottom
  - Method: `log_tool_call(name: str, args: dict)`
  - Method: `log_device_found(ip: str, vendor: str)`
  - Method: `log_finding(finding: str, risk: str)`
- **VALIDATE**: `python -c "from homeguard.tui.widgets.scan_log import ScanLog"`

### Task 9: CREATE src/homeguard/tui/screens/__init__.py

- **IMPLEMENT**: Screen exports
- **VALIDATE**: `python -c "from homeguard.tui.screens import MainScreen"`

### Task 10: CREATE src/homeguard/tui/screens/main.py

- **IMPLEMENT**: Main dashboard screen
- **IMPORTS**: `from textual.screen import Screen`, `from textual.containers import Horizontal, Vertical`
- **LAYOUT**:
```
┌─────────────────────────────────────────────────────┐
│ Header                                              │
├─────────────┬───────────────────────────────────────┤
│ History     │ Device Table                          │
│ ListView    │ (40% height)                          │
│             ├───────────────────────────────────────┤
│             │ Device Panel / Findings Tree (tabs)   │
│             │ (60% height)                          │
├─────────────┴───────────────────────────────────────┤
│ Footer: [S]can [R]eport [Q]uit                      │
└─────────────────────────────────────────────────────┘
```
- **BINDINGS**: s=new_scan, r=view_report, q=quit
- **HANDLERS**: 
  - `on_device_table_device_selected` → update panel
  - `on_list_view_selected` → load historical scan via `load_report(scan_id)`
  - `on_mount` → populate history list via `list_reports()`
- **IMPORTS**: Also import `from homeguard.agent.report import list_reports, load_report`
- **VALIDATE**: `python -c "from homeguard.tui.screens.main import MainScreen"`

### Task 11: CREATE src/homeguard/tui/screens/scan.py

- **IMPLEMENT**: Active scan screen
- **IMPORTS**: `from textual.screen import Screen`, `from textual import work`
- **LAYOUT**:
```
┌─────────────────────────────────────────────────────┐
│ Header: "Scanning..."                               │
├─────────────────────────────────────────────────────┤
│ ProgressBar                                         │
├─────────────────────────────────────────────────────┤
│ Device Table (live updates)                         │
├─────────────────────────────────────────────────────┤
│ Scan Log (real-time)                                │
├─────────────────────────────────────────────────────┤
│ Footer: [C]ancel                                    │
└─────────────────────────────────────────────────────┘
```
- **WORKER**: `@work(exclusive=True, thread=True)` for scan
- **GOTCHA**: Use `call_from_thread()` to update UI from worker
- **VALIDATE**: `python -c "from homeguard.tui.screens.scan import ScanScreen"`

### Task 12: CREATE src/homeguard/tui/app.py

- **IMPLEMENT**: Main HomeGuardApp
- **IMPORTS**: `from textual.app import App`
- **FEATURES**:
  - CSS_PATH = "styles.tcss"
  - SCREENS = {"main": MainScreen, "scan": ScanScreen}
  - on_mount: push MainScreen
  - action_scan: push ScanScreen
  - action_quit: exit app
- **VALIDATE**: `python -c "from homeguard.tui.app import HomeGuardApp; HomeGuardApp()"`

### Task 13: UPDATE src/homeguard/interactive.py

- **IMPLEMENT**: Replace questionary menu with Textual app
- **PATTERN**: Keep `run_interactive()` function signature
- **CHANGE**:
```python
def run_interactive():
    from homeguard.tui import HomeGuardApp
    app = HomeGuardApp()
    app.run()
```
- **VALIDATE**: `python -c "from homeguard.interactive import run_interactive"`

### Task 14: CREATE src/homeguard/tui/scan_runner.py

- **IMPLEMENT**: Adapter to run agent loop with TUI callbacks
- **PATTERN**: Mirror `loop.py` but emit messages instead of printing
- **FEATURES**:
  - `ScanRunner` class with callback methods
  - `on_device_found(device: dict)`
  - `on_tool_call(name: str, args: dict)`
  - `on_finding(finding: str, risk: str)`
  - `on_complete(report: ScanReport)`
- **GOTCHA**: Must be thread-safe for worker
- **VALIDATE**: `python -c "from homeguard.tui.scan_runner import ScanRunner"`

### Task 15: INTEGRATION TEST

- **IMPLEMENT**: Manual test of full flow
- **VALIDATE**: 
```bash
cd /Users/speculari/Python/dynamous-kiro-hackathon
source .venv/bin/activate
homeguard  # Should launch TUI
# Press 's' to start scan
# Verify devices appear in table
# Click device to see details
# Press 'q' to quit
```

---

## TESTING STRATEGY

### Unit Tests

Based on project's pytest patterns, create minimal tests:

```python
# tests/test_tui/test_widgets.py
def test_device_table_add_device():
    table = DeviceTable()
    table.add_device({"ip": "192.168.0.1", "vendor": "Test"})
    assert table.row_count == 1

def test_device_panel_show_device():
    panel = DevicePanel()
    device = DeviceReport(ip="192.168.0.1", mac="aa:bb:cc", ...)
    panel.show_device(device)
    # Verify content updated
```

### Integration Tests

Use Textual's pilot for app testing:
```python
async def test_app_launches():
    app = HomeGuardApp()
    async with app.run_test() as pilot:
        assert app.screen.name == "main"
```

### Edge Cases

- Empty scan (no devices found)
- Scan cancellation mid-way
- Loading corrupted report file
- Very long device list (100+ devices)

---

## VALIDATION COMMANDS

### Level 1: Syntax & Style

```bash
cd /Users/speculari/Python/dynamous-kiro-hackathon
source .venv/bin/activate
ruff check src/homeguard/tui/ --fix
```

### Level 2: Unit Tests

```bash
pytest tests/ -v
```

### Level 3: Import Test

```bash
python -c "from homeguard.tui import HomeGuardApp; print('OK')"
```

### Level 4: Manual Validation

```bash
# Launch app
homeguard

# Expected: TUI dashboard appears
# Press 's' - scan screen appears
# Wait for scan - devices populate table
# Click device - details panel updates
# Press 'q' - app exits cleanly
```

---

## ACCEPTANCE CRITERIA

- [ ] Textual app launches when running `homeguard` without args
- [ ] Device table shows discovered devices in real-time
- [ ] Clicking/selecting device shows details in panel
- [ ] Findings tree shows security issues by risk level
- [ ] Scan history sidebar lists past scans
- [ ] Keyboard shortcuts work (s=scan, q=quit)
- [ ] Scan can be cancelled mid-way
- [ ] All existing tests still pass
- [ ] No ruff linting errors

---

## COMPLETION CHECKLIST

- [ ] All tasks completed in order
- [ ] Each task validation passed
- [ ] All validation commands executed successfully
- [ ] Full test suite passes
- [ ] No linting errors
- [ ] Manual testing confirms feature works
- [ ] Acceptance criteria all met

---

## NOTES

### Design Decisions

1. **Separate screens vs single screen**: Using separate MainScreen and ScanScreen for cleaner separation. Scan screen can be cancelled and returns to main.

2. **Thread worker vs async**: Using `thread=True` because the existing scanner code (`scan_network`, `scan_ports`) is synchronous. Converting to async would require major refactoring.

3. **Callback adapter**: Creating `ScanRunner` as adapter layer rather than modifying `loop.py` directly. This preserves the existing CLI behavior while enabling TUI integration.

4. **Minimal widget customization**: Using Textual's built-in widgets (DataTable, Tree, RichLog) with minimal subclassing to reduce complexity.

### Risks

1. **Thread safety**: Agent loop has many console.print() calls. Need to ensure TUI updates happen via `call_from_thread()`.

2. **Scan interruption**: Current agent loop doesn't support clean cancellation. May need to add cancellation checks.

3. **Report compatibility**: Existing reports should load correctly in new TUI. Test with real scan data.

### Future Enhancements

- Settings screen with form inputs
- Export report to PDF/HTML
- Network topology visualization
- Real-time threat alerts
