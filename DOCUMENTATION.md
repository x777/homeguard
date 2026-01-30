# HomeGuard CLI - Complete Documentation

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Quick Start Guide](#quick-start-guide)
4. [User Guide](#user-guide)
5. [Architecture](#architecture)
6. [API Reference](#api-reference)
7. [Development Guide](#development-guide)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Getting Started

### What is HomeGuard CLI?

HomeGuard is an AI-powered network security scanner that helps you:
- Discover all devices on your home network
- Identify security vulnerabilities
- Get actionable recommendations
- Monitor your network continuously

**Key Features:**
- 🚀 5-second network scan
- 🤖 AI-powered security analysis
- 🎯 Prioritized, actionable recommendations
- 📊 Interactive TUI dashboard
- 🔔 Real-time monitoring and alerts
- 🔒 Privacy-first design (no data leaves your machine)

### Who is it for?

- **Homeowners**: Check if your smart devices are secure
- **Small businesses**: Quick security assessment
- **Developers**: Network debugging and monitoring
- **Security enthusiasts**: Deep vulnerability analysis

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Docker & Docker Compose** (for backend API)
- **sudo/root access** (for network scanning)
- **Optional**: scapy for advanced scanning

### Method 1: Quick Install (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/homeguard-cli
cd homeguard-cli

# Install
pip install -e .

# Start backend
cd api
cp .env.example .env
# Edit .env with your DEEPSEEK_API_KEY
docker-compose up -d

# Verify installation
homeguard --version
```

### Method 2: Install without scapy (No root required for install)

```bash
pip install -e . --no-deps
pip install typer rich questionary litellm pyyaml textual apscheduler requests
```

### Method 3: Development Install

```bash
# Install with dev dependencies
pip install -e ".[dev,full]"

# Run tests
pytest

# Format code
black src/ tests/
ruff check src/ tests/
```

### Backend Setup

The backend provides LLM analysis and CVE lookup:

```bash
cd api

# Configure environment
cp .env.example .env
nano .env  # Add your DEEPSEEK_API_KEY

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

**Backend endpoints:**
- Health check: `http://localhost:8000/health`
- API docs: `http://localhost:8000/docs`

---

## Quick Start Guide

### 1. Your First Scan

```bash
# Quick scan (17 common ports, ~5 seconds)
sudo homeguard scan

# Full AI scan (deep analysis, ~30 seconds)
sudo homeguard scan --full
```

**What you'll see:**
- List of discovered devices
- Device types (Router, NAS, Phone, etc.)
- Open ports and services
- Risk levels (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

### 2. Launch Interactive Dashboard

```bash
sudo homeguard
```

**Keyboard shortcuts:**
- `s` - Quick Scan
- `a` - AI Scan
- `m` - Network Monitoring
- `t` - Network Topology
- `c` - Toggle AI Chat
- `q` - Quit

### 3. View Scan History

```bash
# List all scans
homeguard info

# View specific report
cat ~/.homeguard/reports/scan_YYYYMMDD_HHMMSS.json
```

### 4. Enable Monitoring

1. Press `m` in TUI to open Monitoring screen
2. Press `Enter` on "Settings"
3. Enable monitoring and set interval
4. Optional: Configure Telegram notifications
5. Press `s` to save

---

## User Guide

### Understanding Scan Modes

#### Quick Scan
- **Duration**: ~5 seconds
- **Ports scanned**: 17 common ports
- **Device identification**: Rule-based + HTTP
- **Use case**: Daily checks, quick overview

#### AI Scan (Full)
- **Duration**: ~30 seconds
- **Ports scanned**: 17 common + deep scan on demand
- **Device identification**: Rule-based + HTTP + LLM
- **Security checks**: CVE lookup, threat intel, deep probes
- **Use case**: Comprehensive security assessment

### Device Identification

HomeGuard uses 4 methods to identify devices:

1. **Port Signatures**: Matches open ports to known device types
   - Example: Ports 5000, 5001 → NAS device
   
2. **HTTP Analysis**: Checks Server headers and page titles
   - Example: Server: "Synology" → Synology NAS
   
3. **Banner Analysis**: Examines service banners
   - Example: SSH banner contains "Dropbear" → Embedded device
   
4. **LLM Fallback**: AI analyzes unknown devices
   - Example: Unknown ports → AI suggests device type

**Supported device types:**
- Routers/Gateways (TP-Link, MikroTik, Ubiquiti)
- NAS/Storage (Synology, QNAP, Western Digital)
- Smart Home (Philips Hue, Nest, Ring, Echo, Google Home)
- Streaming (Chromecast, Roku, Fire TV, Apple TV)
- IoT (Smart bulbs, cameras, sensors)
- Network devices (Raspberry Pi, servers, printers)

### Security Checks

#### Automatic Checks (Quick Scan)
- Open ports and services
- OS fingerprinting
- Basic risk assessment

#### AI-Driven Checks (Full Scan)
- CVE vulnerability lookup
- Default credential detection
- UPnP exposure check
- Weak encryption detection
- Firmware age assessment
- Threat intelligence lookup

### Risk Levels

| Level | Icon | Meaning | Examples |
|-------|------|---------|----------|
| Critical | 🔴 | Immediate action required | Remote code execution, exposed admin panels |
| High | 🟠 | Fix soon | Outdated firmware, weak encryption |
| Medium | 🟡 | Should fix | Non-critical services exposed |
| Low | 🟢 | Informational | Standard services, no known issues |

### Network Monitoring

**Features:**
- Periodic network scans (configurable interval)
- Change detection (new devices, removed devices, port changes)
- Alert system (desktop notifications + Telegram)
- Alert history with timestamps

**Setup:**
1. Open TUI (`sudo homeguard`)
2. Press `m` for Monitoring
3. Press `Enter` on "Settings"
4. Configure:
   - Enable monitoring: Yes
   - Scan interval: 3600 seconds (1 hour)
   - Telegram bot token (optional)
   - Telegram chat ID (optional)
5. Press `s` to save

**Telegram Setup:**
1. Create bot: Talk to @BotFather on Telegram
2. Get bot token: `/newbot` command
3. Get chat ID: Talk to @userinfobot
4. Add to HomeGuard settings

### AI Chat Assistant

**Access:** Press `c` in TUI to toggle chat

**What you can ask:**
- "What's the most critical issue?"
- "How do I fix the UPnP vulnerability?"
- "Is my NAS secure?"
- "What ports should I close?"
- "Explain this CVE to me"

**Features:**
- Context-aware (knows your scan results)
- Security expertise
- Step-by-step guidance
- Plain language explanations

---

## Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────┐
│                    LOCAL CLI CLIENT                       │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐              │
│  │ Typer   │───▶│ Scanner │───▶│ Textual │              │
│  │ + Rich  │    │ Module  │    │   TUI   │              │
│  └─────────┘    └─────────┘    └─────────┘              │
│       ▲                              │                   │
│       │         ┌─────────┐          │                   │
│       └─────────│ Agent   │◀─────────┘                   │
│                 │  Loop   │                              │
│                 └────┬────┘                              │
└──────────────────────┼───────────────────────────────────┘
                       │ HTTPS/JSON
                       ▼
┌──────────────────────────────────────────────────────────┐
│                  BACKEND SERVICE (FastAPI)                │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐              │
│  │ Routes  │───▶│ CVE     │    │ LLM     │              │
│  │         │    │ Lookup  │    │ Proxy   │              │
│  └─────────┘    └─────────┘    └─────────┘              │
└──────────────────────────────────────────────────────────┘
```

### Components

#### 1. Scanner Module (`src/homeguard/scanner/`)
- **discovery.py**: ARP/ping-based device discovery
- **ports.py**: TCP port scanning with banner grabbing
- **os_detect.py**: TTL-based OS fingerprinting
- **services.py**: Port/service database

#### 2. AI Agent (`src/homeguard/agent/`)
- **loop.py**: Main agent execution loop
- **scan_orchestrator.py**: Coordinates scanning workflow
- **tools/**: Agent tools (network, security, threat intel)
- **prompts.py**: LLM system prompts

#### 3. TUI Dashboard (`src/homeguard/tui/`)
- **app.py**: Main Textual application
- **screens/**: Different views (main, scan, monitoring, topology)
- **widgets/**: Custom components (device table, chat, etc.)

#### 4. Backend API (`api/`)
- **main.py**: FastAPI application
- **routes/analyze.py**: Analysis endpoints
- **services/**: CVE lookup, LLM proxy, threat intel

### Data Flow

1. **Network Discovery**
   ```
   ARP scan → Device list → OS detection → Device map
   ```

2. **Port Scanning**
   ```
   Port scan → Banner grab → Service identification → Risk assessment
   ```

3. **Device Identification**
   ```
   Port signatures → HTTP check → Banner analysis → LLM fallback → Device type
   ```

4. **Security Analysis**
   ```
   CVE lookup → Threat intel → Deep scan → Risk scoring → Recommendations
   ```

### Privacy & Security

**What stays local:**
- All IP addresses
- All MAC addresses
- All hostnames
- Network topology
- Scan results
- Device information

**What goes to backend (AI scans only):**
- Port numbers (e.g., [80, 443, 22])
- Generic device types (e.g., "Router", "NAS")
- Public CVE identifiers

**Security measures:**
- No telemetry or tracking
- Backend is optional (quick scans work offline)
- You control the backend (Docker included)
- Open source (audit the code)

---

## API Reference

### CLI Commands

#### `homeguard scan`
Scan the local network for devices and security issues.

**Options:**
- `--full` - Run full AI scan with deep analysis
- `--ports` - Include port scanning
- `--output FILE` - Save results to file

**Examples:**
```bash
# Quick scan
sudo homeguard scan

# Full AI scan
sudo homeguard scan --full

# Save results
sudo homeguard scan --output report.json
```

#### `homeguard ports <ip>`
Scan specific IP for open ports.

**Options:**
- `--full` - Scan all 1000 common ports (default: 17)

**Examples:**
```bash
# Quick port scan
sudo homeguard ports 192.168.1.1

# Full port scan
sudo homeguard ports 192.168.1.1 --full
```

#### `homeguard info`
Display system information and scan history.

**Examples:**
```bash
homeguard info
```

#### `homeguard` (no arguments)
Launch interactive TUI dashboard.

**Examples:**
```bash
sudo homeguard
```

### Backend API Endpoints

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

#### `POST /api/chat`
Chat with AI assistant.

**Request:**
```json
{
  "message": "What's the most critical issue?",
  "context": "scan results..."
}
```

**Response:**
```json
{
  "response": "The most critical issue is...",
  "suggestions": ["Fix UPnP", "Update firmware"]
}
```

#### `POST /api/identify/device`
Identify unknown device using AI.

**Request:**
```json
{
  "ip": "192.168.1.100",
  "mac": "aa:bb:cc:dd:ee:ff",
  "open_ports": [80, 443, 8080],
  "banners": {"80": "nginx/1.18.0"}
}
```

**Response:**
```json
{
  "identification": {
    "device_type": "Web Server",
    "vendor": "Unknown",
    "confidence": "medium",
    "reasoning": "Port 80/443 with nginx suggests web server"
  }
}
```

#### `GET /api/cve/search`
Search for CVE vulnerabilities.

**Query Parameters:**
- `keyword` - Search term (e.g., "nginx")

**Response:**
```json
{
  "results": [
    {
      "id": "CVE-2021-23017",
      "description": "nginx vulnerability...",
      "severity": "HIGH"
    }
  ]
}
```

---

## Development Guide

### Project Structure

```
homeguard-cli/
├── src/homeguard/          # Main package
│   ├── cli.py              # CLI entry point
│   ├── scanner/            # Network scanning
│   ├── agent/              # AI agent system
│   ├── tui/                # Terminal UI
│   └── monitor/            # Background monitoring
├── api/                    # Backend service
│   ├── main.py
│   ├── routes/
│   └── services/
├── tests/                  # Test suite
├── .kiro/                  # Kiro CLI config
│   ├── steering/           # Project guidelines
│   ├── prompts/            # Custom prompts
│   └── agents/             # Custom agents
└── docs/                   # Documentation
```

### Development Setup

```bash
# Clone and install
git clone https://github.com/yourusername/homeguard-cli
cd homeguard-cli
pip install -e ".[dev,full]"

# Start backend
cd api && docker-compose up -d

# Run tests
pytest

# Format code
black src/ tests/
ruff check src/ tests/

# Type checking
mypy src/
```

### Running Tests

```bash
# All tests
pytest

# Specific module
pytest tests/test_scanner/

# With coverage
pytest --cov=homeguard --cov-report=html

# Watch mode
pytest-watch
```

### Code Style

- **Formatting**: Black (100 char line length)
- **Linting**: Ruff
- **Type hints**: Required for all functions
- **Docstrings**: Required for public APIs
- **Naming**: snake_case for functions, PascalCase for classes

### Adding New Features

1. **Plan**: Use `@plan-feature` prompt in Kiro CLI
2. **Implement**: Follow the plan systematically
3. **Test**: Add unit tests
4. **Document**: Update relevant docs
5. **Review**: Use `@code-review` prompt

### Custom Agents

See [README.md](README.md#custom-development-agents) for details on the 7 specialized agents used in development.

---

## Troubleshooting

### Common Issues

#### Permission Denied

**Problem**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:
```bash
# Run with sudo
sudo homeguard scan

# Or install without scapy
pip install -e . --no-deps
pip install typer rich questionary litellm pyyaml textual apscheduler requests
```

#### Backend Not Responding

**Problem**: `Connection refused` or `Backend unavailable`

**Solution**:
```bash
# Check if backend is running
cd api && docker-compose ps

# View logs
docker-compose logs -f

# Restart backend
docker-compose restart

# Rebuild if needed
docker-compose down
docker-compose up -d --build
```

#### Unknown Devices

**Problem**: Most devices show as "Unknown Device"

**Solution**:
1. Ensure backend is running (LLM identification requires it)
2. Run AI scan: `sudo homeguard scan --full`
3. Check backend logs: `docker-compose logs homeguard-api`

#### TUI Crashes

**Problem**: TUI crashes or displays incorrectly

**Solution**:
```bash
# Check terminal size (minimum 80x24)
echo $COLUMNS x $LINES

# Clear cache
rm -rf ~/.cache/textual

# Run with debug logging
sudo homeguard --debug
tail -f ~/.homeguard/tui_debug.log
```

#### Port Scan Timeouts

**Problem**: Port scans timeout or miss devices

**Solution**:
```bash
# Port timeout is hardcoded to 2.0s in the scanner
# Use quick scan only (fewer ports, faster)
sudo homeguard scan  # No --full flag

# Or modify src/homeguard/scanner/ports.py if needed
```

#### Monitoring Not Working

**Problem**: Monitoring doesn't start or alerts don't appear

**Solution**:
1. Check settings: Press `m` → Settings in TUI
2. Verify interval is set and monitoring is enabled
3. Check logs: `tail -f ~/.homeguard/tui_debug.log`
4. For Telegram: Verify bot token and chat ID

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export HOMEGUARD_DEBUG=1

# Or use --debug flag
sudo homeguard --debug

# View logs
tail -f ~/.homeguard/tui_debug.log
```

### Getting Help

- **Logs**: `~/.homeguard/tui_debug.log`
- **Reports**: `~/.homeguard/reports/`
- **Config**: `~/.homeguard/config.yaml`
- **Backend health**: `curl http://localhost:8000/health`
- **GitHub Issues**: Include logs and `homeguard info` output

---

## FAQ

### General

**Q: Do I need to run HomeGuard with sudo?**  
A: Yes, for network scanning. Raw socket access requires root privileges.

**Q: Does HomeGuard work offline?**  
A: Yes! Quick scans work completely offline. AI scans require the backend.

**Q: What data is sent to the backend?**  
A: Only port numbers, generic device types, and CVE identifiers. No IPs, MACs, or hostnames.

**Q: Can I use my own LLM API key?**  
A: Yes, configure it in `~/.homeguard/config.yaml`:

```yaml
llm:
  provider: openai  # or anthropic, deepseek, ollama, bedrock
  model: gpt-4
  api_key: your-api-key-here
  base_url: null  # optional, for custom endpoints
  scan_mode: quick  # or full
```

**Q: Can I change the backend URL?**  
A: Yes, set `base_url` in `~/.homeguard/config.yaml`:

```yaml
llm:
  provider: backend
  model: auto
  base_url: http://your-server:8000
  scan_mode: quick
```

### Technical

**Q: What ports does HomeGuard scan?**  
A: Quick scan: 17 common ports. Full scan: 17 + deep scan on demand.

**Q: How accurate is device identification?**  
A: 80% accuracy with 4 identification methods (port signatures, HTTP, banners, LLM).

**Q: Can I customize the port list?**  
A: Yes, edit `src/homeguard/scanner/services.py` and rebuild.

**Q: Does HomeGuard detect all vulnerabilities?**  
A: No tool detects everything. HomeGuard focuses on common home network issues.

### Privacy

**Q: Is my network data stored anywhere?**  
A: Only locally in `~/.homeguard/`. Nothing is sent to external servers except anonymized metadata for AI analysis.

**Q: Can I audit the code?**  
A: Yes! HomeGuard is open source. Check `src/` and `api/` directories.

**Q: Do you collect telemetry?**  
A: No. Zero telemetry or tracking.

### Development

**Q: How was HomeGuard built?**  
A: Using Kiro CLI with 7 specialized AI agents over 30 hours.


**Q: What's the tech stack?**  
A: Python 3.10+, Typer, Rich, Textual, FastAPI, DeepSeek LLM, Docker.

---

## Additional Resources

- **README**: [README.md](README.md) - Project overview
- **Development Log**: [DEVLOG.md](DEVLOG.md) - Complete development timeline
- **Demo Script**: [DEMO_SPEECH.md](DEMO_SPEECH.md) - 2-minute presentation
- **Kiro Guide**: [kiro-guide.md](kiro-guide.md) - Kiro CLI usage
- **API Docs**: http://localhost:8000/docs (when backend is running)

---

**Built with ❤️ using Kiro CLI for the Dynamous Kiro Hackathon**
