# Remediation UI Design Proposal

## Current State
✅ **Backend**: Fully implemented remediation engine with:
- Vulnerability detection (Telnet, SMB v1, weak SSL, UPnP, HTTP admin, default creds)
- Fix plan generation (HTTP API, SSH, local commands, manual guides)
- Dry-run mode for safety
- Verification after fixes
- Severity levels (critical/high/medium)

✅ **Data Flow**: 
- Scans detect fixable vulnerabilities
- Stored in `device_data["fixable_vulnerabilities"]`
- Displayed in device panel (shows count + top 3)

❌ **Missing**: No way to actually execute fixes from UI

---

## Proposed UI Integration

### Option 1: Quick Fix Button (Recommended) ⭐
**Location**: Device Panel (right side)
**Design**: Add "Fix Issues" button when fixable vulnerabilities exist

```
┌─ Device Details ─────────────────────────┐
│ 📱 192.168.0.101                         │
│ Type: Router/Gateway                     │
│ Vendor: TP-Link                          │
│                                          │
│ 🔧 Fixable Issues (3):                  │
│   🔴 Telnet service exposed              │
│   🟠 Weak SSL/TLS configuration          │
│   🟡 UPnP enabled                        │
│                                          │
│ [Fix All Issues] [Review Fixes]          │
└──────────────────────────────────────────┘
```

**Interaction Flow**:
1. User clicks "Fix All Issues" → Modal appears
2. Modal shows fix plan with commands
3. User reviews and confirms
4. Execute fixes with progress indicator
5. Show results (success/failure per fix)
6. Re-scan device to verify

**Keybinding**: `f` = Fix issues for selected device

---

### Option 2: Remediation Screen (Full Featured)
**Location**: New screen accessible via `r` key
**Design**: Dedicated remediation dashboard

```
┌─ Remediation Center ─────────────────────────────────────────┐
│                                                               │
│ Devices with Fixable Issues (3)                              │
│ ┌───────────────────────────────────────────────────────────┐│
│ │ IP            │ Issues │ Severity │ Status    │ Action   ││
│ ├───────────────┼────────┼──────────┼───────────┼──────────┤│
│ │ 192.168.0.1   │ 3      │ 🔴 CRIT  │ Pending   │ [Fix]    ││
│ │ 192.168.0.101 │ 2      │ 🟠 HIGH  │ Pending   │ [Fix]    ││
│ │ 192.168.0.105 │ 1      │ 🟡 MED   │ Fixed ✓   │ [Verify] ││
│ └───────────────────────────────────────────────────────────┘│
│                                                               │
│ Selected Device: 192.168.0.1                                 │
│ ┌─ Fix Plan ──────────────────────────────────────────────┐ │
│ │ 🔴 Telnet Exposed (Port 23)                             │ │
│ │   Method: SSH Command                                   │ │
│ │   Command: systemctl stop telnet                        │ │
│ │   Risk: Low | Reversible: Yes | Time: 30s              │ │
│ │                                                          │ │
│ │ 🟠 Weak SSL (Port 443)                                  │ │
│ │   Method: HTTP API                                      │ │
│ │   Command: curl -X POST http://192.168.0.1/admin/ssl... │ │
│ │   Risk: Low | Reversible: Yes | Time: 30s              │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                               │
│ [Fix Selected] [Fix All] [Dry Run] [Cancel]                  │
└───────────────────────────────────────────────────────────────┘
```

**Features**:
- Table of all devices with fixable issues
- Click device to see detailed fix plan
- Batch fix multiple devices
- Dry-run mode to preview changes
- Status tracking (Pending/In Progress/Fixed/Failed)
- Verification after fixes

**Keybindings**:
- `r` = Open remediation screen
- `f` = Fix selected device
- `a` = Fix all devices
- `d` = Dry run (preview)
- `v` = Verify fixes

---

### Option 3: Inline Fix Actions (Minimal)
**Location**: Device table context menu
**Design**: Right-click or press `f` on device row

```
┌─ Devices ────────────────────────────────┐
│ IP            │ Type   │ Risk  │ Ports   │
├───────────────┼────────┼───────┼─────────┤
│ 192.168.0.1   │ Router │ 🔴 CR │ 23,80.. │ ← [f] Fix 3 issues
│ 192.168.0.101 │ Phone  │ 🟢 LO │ 80,443  │
└──────────────────────────────────────────┘

Press 'f' → Quick modal:
┌─ Fix Issues: 192.168.0.1 ────────────────┐
│ Found 3 fixable vulnerabilities:          │
│   🔴 Telnet exposed                       │
│   🟠 Weak SSL                             │
│   🟡 UPnP enabled                         │
│                                           │
│ [Fix All] [Review] [Cancel]               │
└───────────────────────────────────────────┘
```

---

## Recommended Implementation: Hybrid Approach

### Phase 1: Quick Fix Button (1-2 hours)
Add to device panel:
1. Show "Fix Issues" button when `fixable_vulnerabilities` exists
2. Click → Modal with fix plan preview
3. Confirm → Execute fixes with progress
4. Show results modal

**Files to modify**:
- `src/homeguard/tui/widgets/device_panel.py` - Add button
- `src/homeguard/tui/screens/main.py` - Handle fix action
- Create `src/homeguard/tui/widgets/fix_modal.py` - Fix confirmation modal

### Phase 2: Remediation Screen (2-3 hours)
Full-featured remediation dashboard:
1. Create `src/homeguard/tui/screens/remediation.py`
2. Table of devices with issues
3. Detailed fix plans
4. Batch operations
5. Status tracking

---

## Safety Features (Critical!)

### Must-Have Safeguards:
1. **Dry-Run First**: Always show what will be executed
2. **Confirmation Required**: Never auto-execute without user approval
3. **Backup Warning**: Warn user to have backup access
4. **Rollback Info**: Show if fix is reversible
5. **Manual Fallback**: Provide manual instructions if auto-fix fails
6. **Verification**: Re-scan after fixes to confirm

### UI Safety Indicators:
```
Risk Level: 🟢 Low | 🟡 Medium | 🔴 High
Reversible: ✅ Yes | ❌ No
Requires: 🔑 Admin Access | 🌐 Network Access
```

---

## Code Structure

### New Files:
```
src/homeguard/tui/widgets/
├── fix_modal.py          # Fix confirmation modal
└── fix_progress.py       # Progress indicator during fixes

src/homeguard/tui/screens/
└── remediation.py        # Full remediation screen (Phase 2)
```

### Integration Points:
```python
# In device_panel.py
if device.get("fixable_vulnerabilities"):
    yield Button("Fix Issues", id="fix_button", variant="success")

# In main.py
@on(Button.Pressed, "#fix_button")
def handle_fix_button(self):
    self.show_fix_modal(self.selected_device)

# New fix_modal.py
class FixModal(ModalScreen):
    def __init__(self, device, vulnerabilities):
        # Show fix plan
        # Dry-run preview
        # Confirm/Cancel buttons
```

---

## User Experience Flow

### Happy Path:
1. User runs AI scan
2. Device shows "🔧 3 fixable issues"
3. User clicks device → sees issues in panel
4. User clicks "Fix Issues" button
5. Modal shows fix plan with commands
6. User reviews and clicks "Execute"
7. Progress bar shows fixes being applied
8. Success modal: "✅ Fixed 3/3 issues"
9. Device re-scanned automatically
10. Risk level updated in table

### Error Path:
1. Fix fails (network error, auth failure, etc.)
2. Show error modal with details
3. Offer: "Try Again" | "Manual Instructions" | "Skip"
4. If manual: Show step-by-step guide
5. User can mark as "Fixed Manually" after completion

---

## Recommendation

**Start with Option 1 (Quick Fix Button)** because:
- ✅ Minimal code changes
- ✅ Integrates with existing UI
- ✅ Immediate value to users
- ✅ Can expand to Option 2 later
- ✅ Follows "progressive disclosure" UX pattern

**Implementation Priority**:
1. Add fix button to device panel (30 min)
2. Create fix confirmation modal (1 hour)
3. Wire up remediation execution (30 min)
4. Add progress indicator (30 min)
5. Add results modal (30 min)

**Total: ~3 hours for full working feature**

---

## Security Considerations

⚠️ **Important**: Remediation executes system commands. Must:
1. Validate all inputs (IP addresses, commands)
2. Never allow command injection
3. Run with least privilege
4. Log all remediation attempts
5. Require explicit user consent
6. Show exactly what will be executed
7. Timeout long-running commands
8. Handle failures gracefully

The current `remediation.py` already has these safeguards built-in.
