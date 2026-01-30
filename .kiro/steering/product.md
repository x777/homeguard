# Product Overview

## Product Purpose
HomeGuard CLI is an AI-powered network security assessment tool that scans home networks, discovers connected devices, evaluates their security posture, and uses an LLM agent to intelligently analyze results, request additional scans when needed, and generate clear, actionable recommendations. The LLM acts as a security expert that controls the scanning process to get comprehensive results.

## Target Users
- **Technical users & developers**: Quick security assessments without complex tooling
- **Non-technical end users**: Simple, understandable security checks for peace of mind
- **Small businesses**: Basic office network security evaluation

## Key Features
- **AI-Powered**: All features driven by LLM agent
- Network device discovery and enumeration
- Port scanning and service detection
- CVE lookup for discovered services/devices
- **LLM Agent Mode**: AI controls scanning to get complete results
- **Human-in-the-loop**: User approval required for sensitive actions
- **Backend Proxy (Default)**: No API keys needed - uses HomeGuard backend
- **Multi-provider Support**: Users can optionally use their own API keys (OpenAI, Anthropic, DeepSeek, Ollama)
- Plain-language security recommendations
- Rich CLI output with clear risk indicators
- Cross-platform support (Windows/macOS/Linux)

## Business Objectives
- Make network security accessible to non-experts
- Provide intelligent, adaptive security scanning
- Reduce barrier to entry for home network security assessment

## User Journey
1. User runs HomeGuard CLI
2. CLI performs initial scan (devices, ports)
3. **LLM Agent analyzes results** and decides if more info needed
4. **If LLM requests action**: User sees what LLM wants to do and approves/denies
5. Loop continues until LLM has enough information
6. LLM generates comprehensive security report with recommendations
7. **For fixes**: LLM explains what it wants to do, user must approve each step

## Safety & User Control (Critical)

### Action Categories
| Category | Examples | User Approval |
|----------|----------|---------------|
| **Read-only** | Scan network, check ports, lookup CVE | Auto-approved |
| **Informational** | Get OS details, banner grab | Auto-approved |
| **Sensitive** | Deep scan specific device | Ask user first |
| **Dangerous** | Modify settings, apply fixes | Always require explicit approval |

### Human-in-the-Loop Flow
```
LLM: "I found open port 445 (SMB). I'd like to run a deeper scan to check for vulnerabilities."
     [Allow] [Deny] [Ask me each time]

LLM: "Found vulnerability CVE-2017-0144. I recommend disabling SMBv1. Should I show you how?"
     [Show instructions] [Skip]

LLM: "To fix this, I need to run: 'netsh advfirewall firewall add rule...'"
     ⚠️ This will modify your system settings.
     [Run command] [Show me first] [Cancel]
```

### Safety Principles
1. **Transparency**: Always show what LLM wants to do before doing it
2. **Reversibility**: Prefer recommendations over automatic changes
3. **Escalation**: More dangerous = more confirmation required
4. **Audit trail**: Log all LLM decisions and user approvals
5. **Offline mode**: Can run without LLM (basic scan only)

## Success Criteria
- Accurate device discovery and port scanning
- LLM successfully identifies issues and requests appropriate follow-up scans
- Clear, actionable recommendations
- **Zero dangerous actions without user approval**
- User feels in control at all times
- Works with multiple LLM providers
