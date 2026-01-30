# Feature: LLM Agent System

## Feature Description

An agentic LLM system that controls the CLI to perform intelligent security assessments. The LLM can request additional scans, analyze results, and suggest fixes - with human-in-the-loop approval for sensitive actions.

## User Story

As a home network user
I want an AI assistant to guide my security scan
So that I get comprehensive results without needing security expertise

## Feature Metadata

**Feature Type**: New Capability
**Estimated Complexity**: High
**Primary Systems Affected**: CLI, new agent module
**Dependencies**: litellm (multi-provider LLM), pydantic

---

## ARCHITECTURE

### Agent Loop Flow
```
┌─────────────────────────────────────────────────────────┐
│  User starts "AI Scan"                                  │
│         │                                               │
│         ▼                                               │
│  ┌─────────────┐                                        │
│  │ Initial     │ ← scan_network, scan_ports             │
│  │ Scan        │                                        │
│  └──────┬──────┘                                        │
│         │                                               │
│         ▼                                               │
│  ┌─────────────┐    ┌─────────────┐                    │
│  │ LLM         │───▶│ Tool Call?  │                    │
│  │ Analysis    │    └──────┬──────┘                    │
│  └─────────────┘           │                           │
│                    ┌───────┴───────┐                   │
│                    ▼               ▼                   │
│              ┌──────────┐   ┌──────────┐              │
│              │ Yes:     │   │ No:      │              │
│              │ Execute  │   │ Report   │              │
│              │ Tool     │   │ Done     │              │
│              └────┬─────┘   └──────────┘              │
│                   │                                    │
│                   ▼                                    │
│              ┌──────────┐                              │
│              │ Approval │ ← If sensitive/dangerous    │
│              │ Required?│                              │
│              └────┬─────┘                              │
│                   │                                    │
│         ┌────────┴────────┐                           │
│         ▼                 ▼                           │
│    [Auto-approve]   [Ask User]                        │
│         │                 │                           │
│         └────────┬────────┘                           │
│                  ▼                                    │
│         ┌──────────────┐                              │
│         │ Execute &    │                              │
│         │ Loop Back    │──────────────────────────┐   │
│         └──────────────┘                          │   │
│                  ▲                                │   │
│                  └────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Tool Definitions
```python
TOOLS = [
    {
        "name": "scan_network",
        "description": "Discover devices on the local network",
        "risk": "low",
        "auto_approve": True
    },
    {
        "name": "scan_ports", 
        "description": "Scan a device for open ports",
        "parameters": {"ip": "string", "mode": "quick|full"},
        "risk": "low",
        "auto_approve": True
    },
    {
        "name": "lookup_cve",
        "description": "Look up CVEs for a service/version",
        "parameters": {"service": "string", "version": "string"},
        "risk": "low", 
        "auto_approve": True
    },
    {
        "name": "suggest_fix",
        "description": "Generate fix instructions (text only)",
        "risk": "low",
        "auto_approve": True
    },
    {
        "name": "run_command",
        "description": "Execute a system command to fix an issue",
        "parameters": {"command": "string", "reason": "string"},
        "risk": "critical",
        "auto_approve": False  # ALWAYS ask user
    }
]
```

---

## FILES TO CREATE

```
src/homeguard/
├── agent/
│   ├── __init__.py
│   ├── llm.py          # LLM provider abstraction (litellm)
│   ├── tools.py        # Tool definitions and execution
│   ├── loop.py         # Agent loop logic
│   └── config.py       # Configuration management
└── interactive.py      # Update with AI Scan option
```

---

## STEP-BY-STEP TASKS

### Task 1: CREATE `src/homeguard/agent/config.py`

Configuration management for LLM providers.

```python
"""LLM configuration management."""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

CONFIG_PATH = Path.home() / ".homeguard" / "config.yaml"

@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    
def load_config() -> LLMConfig:
    """Load config from file or environment."""
    ...

def save_config(config: LLMConfig) -> None:
    """Save config to file."""
    ...

def setup_wizard() -> LLMConfig:
    """Interactive setup for LLM configuration."""
    ...
```

---

### Task 2: CREATE `src/homeguard/agent/llm.py`

LLM provider abstraction using litellm.

```python
"""LLM provider abstraction."""

from litellm import completion
from .config import LLMConfig

SYSTEM_PROMPT = '''You are HomeGuard, a network security assistant.
You help users scan their home network and identify security issues.

You have access to these tools:
- scan_network: Discover devices on the network
- scan_ports(ip, mode): Scan a device for open ports
- lookup_cve(service, version): Check for known vulnerabilities
- suggest_fix(issue): Generate fix instructions
- run_command(command, reason): Execute a fix (REQUIRES USER APPROVAL)

Always explain what you're doing and why.
For dangerous actions, warn the user clearly.
'''

def chat(messages: list, tools: list, config: LLMConfig) -> dict:
    """Send message to LLM and get response with tool calls."""
    ...
```

---

### Task 3: CREATE `src/homeguard/agent/tools.py`

Tool definitions and safe execution.

```python
"""Agent tools with safety controls."""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Any

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Tool:
    name: str
    description: str
    function: Callable
    risk: RiskLevel
    auto_approve: bool

def get_tools() -> list[Tool]:
    """Get all available tools."""
    ...

def execute_tool(tool: Tool, args: dict, approved: bool = False) -> Any:
    """Execute a tool with safety checks."""
    ...
```

---

### Task 4: CREATE `src/homeguard/agent/loop.py`

Main agent loop with human-in-the-loop.

```python
"""Agent loop with human-in-the-loop safety."""

from rich.console import Console
from rich.panel import Panel
import questionary

def request_approval(tool_name: str, args: dict, reason: str) -> bool:
    """Ask user for approval before executing sensitive action."""
    ...

def run_agent_loop(config: LLMConfig) -> None:
    """Run the agent loop until complete."""
    ...
```

---

### Task 5: UPDATE `src/homeguard/interactive.py`

Add "🤖 AI Security Scan" option to menu.

---

### Task 6: ADD dependencies

```toml
# pyproject.toml
dependencies = [
    ...
    "litellm>=1.0.0",
    "pyyaml>=6.0",
]
```

---

## SAFETY IMPLEMENTATION

### Approval Flow UI
```
╭─────────────────────────────────────────────────────────╮
│ 🤖 AI wants to perform an action                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Action: Run system command                              │
│ Risk Level: ⚠️  CRITICAL                                │
│                                                         │
│ Command:                                                │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ netsh advfirewall firewall add rule name="Block    │ │
│ │ SMB" dir=in action=block protocol=tcp localport=445│ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Reason: Block dangerous SMB port to prevent            │
│ WannaCry-style attacks                                  │
│                                                         │
│ ? Allow this action?                                    │
│   ❯ ✅ Yes, run it                                      │
│     📋 Copy command (I'll run it myself)               │
│     ❌ No, skip this                                    │
│     🛑 Stop AI scan                                     │
╰─────────────────────────────────────────────────────────╯
```

---

## VALIDATION COMMANDS

```bash
# Test config
python -c "from homeguard.agent.config import load_config; print(load_config())"

# Test LLM connection
homeguard ai-test

# Run AI scan
homeguard  # Select "AI Security Scan" from menu
```

---

## ACCEPTANCE CRITERIA

- [ ] LLM can request and execute scan tools
- [ ] User approval required for sensitive actions
- [ ] Clear UI showing what AI wants to do
- [ ] Multiple LLM providers work (OpenAI, DeepSeek, Ollama)
- [ ] Config saved to ~/.homeguard/config.yaml
- [ ] Graceful fallback if no LLM configured
- [ ] All dangerous actions logged
