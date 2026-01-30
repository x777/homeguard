# How to Integrate New Features into HomeGuard UI

## Understanding the UI Architecture

HomeGuard has **3 UI layers**:

```
┌─────────────────────────────────────────┐
│              CLI Commands               │
│  homeguard scan, homeguard ports, etc  │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│           Interactive TUI               │
│    Textual-based terminal interface    │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│            AI Agent Loop                │
│      LLM-powered autonomous scanning    │
└─────────────────────────────────────────┘
```

## Integration Points by UI Layer

### 1. **CLI Commands** (`src/homeguard/cli.py`)

**When to integrate here**: Simple, direct features that enhance basic scanning

**How to integrate**:
```python
@app.command()
def scan(...):
    # Your existing scan logic
    
    # ADD: New feature integration
    if with_new_feature:
        from homeguard.agent.tools import execute_tool
        result = execute_tool("your_new_tool", {"param": value})
        if result.success:
            # Update device data
            device.new_attribute = result.data
    
    # Display results with new data
    table.add_column("New Column")
    table.add_row(..., device.new_attribute)
```

**Example**: Adding fingerprinting to port scans
```python
# In scan() function after port scanning:
fp_result = execute_tool("fingerprint_device", {"ip": ip, "device_data": data})
device.fingerprint_id = fp_result.data.get("fingerprint_id", "")[:8]
```

### 2. **TUI Screens** (`src/homeguard/tui/screens/`)

**When to integrate here**: Interactive features that need user input/display

**Key files**:
- `main.py` - Dashboard with device table
- `scan.py` - Active scanning screen
- `topology.py` - Network visualization

**How to integrate**:

#### A. **Add to Scan Process** (`scan.py`):
```python
def run_scan(self):
    # Existing scan logic...
    
    # ADD: New feature during scan
    if self.should_run_feature():
        ui(log.log_info, "Running new feature...")
        result = execute_tool("new_feature", {"ip": ip})
        device_data["new_data"] = result.data
        ui(table.add_device, device_data)
```

#### B. **Add to Device Display** (`main.py` + widgets):
```python
# In DevicePanel widget:
def _render_device(self, device):
    # Existing device info...
    
    # ADD: New feature display
    if device.get("new_feature_data"):
        text.append("\n🆕 New Feature:\n", style="bold")
        text.append(f"  Data: {device['new_feature_data']}\n")
```

#### C. **Add New Screen**:
```python
# Create new file: src/homeguard/tui/screens/new_feature.py
class NewFeatureScreen(Screen):
    def compose(self):
        yield Header()
        yield YourNewWidget()
        yield Footer()

# Register in main.py:
def action_new_feature(self):
    self.app.push_screen(NewFeatureScreen())
```

### 3. **AI Agent Integration** (`src/homeguard/agent/`)

**When to integrate here**: Complex features that need AI decision-making

**Key files**:
- `tools/definitions.py` - Tool definitions for LLM
- `tools/executor.py` - Tool implementations  
- `prompts.py` - System prompts
- `loop.py` - Agent execution flow

**How to integrate**:

#### A. **Add New Tool**:
```python
# 1. Add to definitions.py:
TOOL_DEFINITIONS.append({
    "type": "function",
    "function": {
        "name": "your_new_tool",
        "description": "What it does",
        "parameters": {
            "type": "object",
            "properties": {
                "param": {"type": "string", "description": "Parameter description"}
            },
            "required": ["param"]
        }
    }
})

# 2. Add to executor.py:
elif name == "your_new_tool":
    param = arguments.get("param")
    result = your_implementation(param)
    return ToolResult(success=True, data=result)

# 3. Update prompts.py:
## Your Tools
- your_new_tool(param): Description of what it does
```

#### B. **Add to Scan Flow**:
```python
# In scan_orchestrator.py or loop.py:
def handle_scan_ports(self, ...):
    # Existing logic...
    
    # ADD: Auto-run new feature
    if self.should_run_new_feature(device_data):
        result = execute_tool("your_new_tool", {"param": value})
        device_data["new_feature_result"] = result.data
```

## Step-by-Step Integration Process

### Step 1: **Implement Core Logic**
```python
# src/homeguard/agent/tools/your_feature.py
def your_feature_function(param: str) -> dict:
    """Your feature implementation."""
    # Do the work
    return {"result": "data"}
```

### Step 2: **Add Tool Definition**
```python
# src/homeguard/agent/tools/definitions.py
{
    "type": "function", 
    "function": {
        "name": "your_feature",
        "description": "Brief description",
        "parameters": {...}
    }
}
```

### Step 3: **Add Tool Executor**
```python
# src/homeguard/agent/tools/executor.py
elif name == "your_feature":
    result = your_feature_function(arguments.get("param"))
    return ToolResult(success=True, data=result)
```

### Step 4: **Choose Integration Level**

**Option A: CLI Only** (Simple)
```python
# Add to cli.py scan() function
result = execute_tool("your_feature", {"param": value})
```

**Option B: TUI Only** (Interactive)
```python
# Add to scan.py run_scan() method
result = execute_tool("your_feature", {"param": value})
ui(log.log_info, f"Feature result: {result.data}")
```

**Option C: AI Agent** (Autonomous)
```python
# Add to prompts.py and let LLM decide when to use it
# LLM will automatically call your_feature when appropriate
```

**Option D: All Levels** (Complete)
```python
# Add to all three: CLI, TUI, and Agent
# Feature available everywhere
```

### Step 5: **Update Display**
```python
# Add to widgets/device_panel.py or cli.py table
if device.get("your_feature_data"):
    # Show the new data to user
```

## Real Example: How I Added Fingerprinting

### 1. **Core Logic**:
```python
# tools/fingerprint.py
class DeviceFingerprinter:
    def create_fingerprint(self, device_data): ...
```

### 2. **Tool Definition**:
```python
# tools/definitions.py
{"name": "fingerprint_device", "parameters": {...}}
```

### 3. **Integration**:
```python
# CLI (cli.py):
fp_result = execute_tool("fingerprint_device", {...})
device.fingerprint_id = fp_result.data.get("fingerprint_id")

# TUI (scan.py):
fp_result = execute_tool("fingerprint_device", {...})
device_data["fingerprint_id"] = fp_result.data.get("fingerprint_id")

# Agent (scan_orchestrator.py):
# Automatically runs during scans
```

### 4. **Display**:
```python
# CLI table shows fingerprint column
# TUI device panel shows fingerprint info
# Reports include fingerprint data
```

## Best Practices

1. **Start Simple**: Add to CLI first, then TUI, then Agent
2. **Follow Patterns**: Look at existing tools for structure
3. **User Control**: Require approval for dangerous operations
4. **Graceful Failure**: Handle errors without breaking scans
5. **Consistent Display**: Show feature data in all relevant UIs
6. **Test Integration**: Verify feature works in all modes

This approach ensures your feature integrates naturally into HomeGuard's existing user experience!

## Common Integration Patterns

### Pattern 1: **Scan Enhancement**
Add data collection during existing scans:
```python
# In scan process:
enhanced_data = execute_tool("enhance_scan", {"device": device_data})
device_data.update(enhanced_data.data)
```

### Pattern 2: **Post-Scan Analysis**
Add analysis after scan completion:
```python
# After scan completes:
analysis = execute_tool("analyze_results", {"devices": all_devices})
report.add_analysis(analysis.data)
```

### Pattern 3: **Interactive Action**
Add user-triggered actions:
```python
# In TUI screen:
def action_new_feature(self):
    selected_device = self.get_selected_device()
    result = execute_tool("interactive_feature", {"device": selected_device})
    self.show_result(result)
```

### Pattern 4: **Background Processing**
Add continuous monitoring:
```python
# In background worker:
@work(exclusive=True)
async def monitor_feature(self):
    while self.monitoring:
        result = execute_tool("background_check", {})
        self.update_ui(result)
        await asyncio.sleep(60)
```

## Testing Your Integration

### 1. **Unit Tests**
```python
def test_your_feature():
    result = execute_tool("your_feature", {"param": "test"})
    assert result.success
    assert "expected_data" in result.data
```

### 2. **Integration Tests**
```python
def test_cli_integration():
    # Test CLI shows new feature
    pass

def test_tui_integration():
    # Test TUI displays new feature
    pass

def test_agent_integration():
    # Test AI uses new feature appropriately
    pass
```

### 3. **Manual Testing**
- Run `homeguard scan --ports` (CLI)
- Run TUI and press "s" (Quick Scan)
- Run TUI and press "a" (AI Scan)
- Verify feature works in all modes

This guide provides a complete framework for adding any new feature to HomeGuard's multi-layered UI architecture!
