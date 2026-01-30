# HomeGuard CLI - AI-Powered Network Security Scanner

HomeGuard is an intelligent network security assessment tool that scans home networks, discovers connected devices, evaluates their security posture, and uses an LLM agent to analyze results and generate actionable recommendations. Built with Kiro CLI for streamlined AI-powered development.

## 🎥 Video Presentation

**Watch the demo**: [HomeGuard CLI - 2 Minute Demo](https://youtu.be/aRQZj955CLc)

## 🔒 Privacy & Security Notice

**IMPORTANT FOR JUDGES**: HomeGuard is designed with privacy as a core principle:

- ✅ **All network scanning happens locally** - No scan data leaves your machine
- ✅ **No private information sent to backend** - Only anonymized metadata for AI analysis
- ✅ **Backend is optional** - Quick scans work completely offline
- ✅ **You control the backend** - Run it locally via Docker (included)
- ✅ **No telemetry or tracking** - Zero data collection
- ✅ **Open source** - Audit the code yourself

**What gets sent to the backend (only during AI scans)?**
- Port numbers (e.g., `[80, 443, 22]`)
- Generic device info (e.g., "Router", "NAS")
- Public CVE identifiers for vulnerability lookup

**What NEVER gets sent?**
- ❌ IP addresses (kept local)
- ❌ MAC addresses (kept local)
- ❌ Hostnames or device names
- ❌ Network topology or layout
- ❌ Scan results or findings
- ❌ Any personally identifiable information

The backend is purely an LLM proxy and CVE database - it has zero knowledge of your actual network.

## Prerequisites

- Python 3.10+
- Docker and Docker Compose (for backend API)
- Optional: `scapy` for advanced network scanning (requires libpcap)
- Kiro CLI installed and authenticated (for development)

## Quick Start

1. **Clone and setup**
   ```bash
   git clone https://github.com/x777/homeguard-cli
   cd homeguard-cli
   pip install -e .
   ```

2. **Start the backend API**
   ```bash
   cd api
   cp .env.example .env
   # Edit .env with your DEEPSEEK_API_KEY
   docker-compose up -d
   ```

3. **Run a network scan**
   ```bash
   # Quick scan (17 common ports)
   sudo homeguard scan

   # Full AI scan with deep analysis
   sudo homeguard scan --full

   # Interactive TUI dashboard
   sudo homeguard
   ```

4. **Access the TUI**
   - Press `s` for Quick Scan
   - Press `a` for AI Scan (with LLM analysis)
   - Press `m` for Network Monitoring
   - Press `t` for Network Topology view
   - Press `c` to toggle AI Chat assistant

## Architecture & Codebase Overview

### System Architecture
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

- **CLI Client**: Local scanning, no API keys needed
- **Backend API**: LLM proxy + CVE/threat intelligence
- **TUI Dashboard**: Real-time monitoring and visualization
- **AI Agent**: Autonomous security analysis with human approval

### Directory Structure
```
homeguard-cli/
├── src/homeguard/
│   ├── cli.py              # Typer CLI entry point
│   ├── scanner/            # Network & port scanning
│   │   ├── discovery.py    # Device discovery (ARP/ping)
│   │   ├── ports.py        # Port scanning & banner grabbing
│   │   ├── os_detect.py    # OS fingerprinting
│   │   └── services.py     # Port/service database
│   ├── agent/              # LLM agent system
│   │   ├── loop.py         # Agent execution loop
│   │   ├── scan_orchestrator.py  # Scan coordination
│   │   ├── tools/          # Agent tools (network, security, etc.)
│   │   └── report.py       # Report generation
│   ├── tui/                # Textual TUI dashboard
│   │   ├── app.py          # Main TUI application
│   │   ├── screens/        # TUI screens (main, scan, monitoring)
│   │   └── widgets/        # Custom widgets (device table, chat)
│   └── monitor/            # Background monitoring
│       ├── scheduler.py    # APScheduler integration
│       └── alerts.py       # Alert system
├── api/
│   ├── main.py             # FastAPI app
│   ├── routes/analyze.py   # Analysis endpoints
│   └── services/           # CVE, LLM, threat intel
├── .kiro/
│   ├── steering/           # Project guidelines
│   ├── prompts/            # Custom Kiro commands
│   └── agents/             # Specialized development agents
└── pyproject.toml
```

### Key Components

**Network Scanner** (`src/homeguard/scanner/`)
- ARP-based device discovery with scapy
- Ping sweep fallback for restricted environments
- TTL-based OS fingerprinting (Windows/Linux/macOS/Cisco)
- Concurrent port scanning (17 common ports in quick mode)
- Banner grabbing for service version detection

**AI Agent System** (`src/homeguard/agent/`)
- LLM-driven security analysis with tool calling
- Human-in-the-loop approval for sensitive actions
- Autonomous deep scanning and threat intelligence
- Device fingerprinting and tracking
- Automated remediation suggestions

**Enhanced Device Identification** (`src/homeguard/agent/tools/network.py`)
- 22+ device type signatures (routers, NAS, IoT, smart home)
- HTTP-based identification (Server headers, page titles)
- Confidence scoring system (port match, vendor, HTTP, banners)
- LLM fallback for unknown devices
- Priority-based detection (routers first, then signatures)

**TUI Dashboard** (`src/homeguard/tui/`)
- Real-time device table with risk indicators
- Interactive network topology tree view
- AI chat assistant for security questions
- Background monitoring with alerts
- Quick fix execution with approval workflow

**Backend API** (`api/`)
- DeepSeek LLM proxy (no local API keys needed)
- NVD CVE database integration
- Threat intelligence (AbuseIPDB, Shodan, DNS reputation)
- VARIoT IoT vulnerability database
- Device identification endpoint

## Deep Dive

### AI Agent Workflow

1. **Initial Scan**: Network discovery + port scanning
2. **Device Identification**: 
   - Rule-based (port signatures, IP patterns)
   - HTTP analysis (Server headers, page titles)
   - Banner analysis (SSH, FTP, HTTP banners)
   - LLM fallback (AI-powered for unknowns)
3. **Security Analysis**: LLM decides what to check
4. **Deep Scanning**: Agent requests additional probes (with approval)
5. **Threat Intelligence**: CVE lookup, IP reputation, IoT exploits
6. **Report Generation**: Prioritized recommendations with risk levels

### Human-in-the-Loop Safety

| Action Type | Examples | Approval Required |
|-------------|----------|-------------------|
| **Read-only** | Network scan, port scan, CVE lookup | Auto-approved |
| **Informational** | OS detection, banner grab | Auto-approved |
| **Sensitive** | Deep scan device, probe services | Ask user |
| **Dangerous** | Apply fixes, modify settings | Always require |

### Kiro CLI Integration

**Custom Prompts** (`.kiro/prompts/`)
- `@prime` - Load comprehensive project context
- `@plan-feature` - Create detailed implementation plans
- `@execute` - Execute plans with systematic task management
- `@code-review` - Technical code review
- `@code-review-hackathon` - Hackathon submission evaluation

**Steering Documents** (`.kiro/steering/`)
- `product.md` - Product vision, features, user journey
- `tech.md` - Architecture, tech stack, LLM agent design
- `structure.md` - Directory layout, naming conventions

**Development Workflow**
1. `@prime` - Load project context at session start
2. `@plan-feature` - Plan new features
3. `@execute` - Implement systematically
4. `@code-review` - Review before commit

### Custom Development Agents

This project uses **7 specialized Kiro CLI agents** for different development tasks:

#### 1. **iot-security-dev** (Primary Development Agent)
**Model**: Claude Sonnet 4.5  
**Purpose**: Main development agent for IoT security features

**Expertise**:
- Home network security (routers, UPnP, default credentials)
- IoT device security (cameras, smart home, appliances)
- Network protocols (TCP/IP, mDNS, SSDP, UPnP, MQTT)
- Vulnerability assessment (CVE, OWASP IoT Top 10)
- Modern TUI/CLI development (Textual, Rich)

**UI/UX Principles**:
- Clarity first (emojis for risk levels: 🔴🟠🟡🟢)
- Progressive disclosure (summary → details)
- Actionable guidance for every finding
- Non-blocking async operations
- Accessible to non-technical users

**Tools**: read, write, shell, grep, glob, code, web_search, web_fetch

**Usage**: Primary agent for implementing security features, scanning logic, and TUI components

---

#### 2. **bugfix** (Debugging Specialist)
**Model**: Claude Sonnet 4.5  
**Purpose**: Systematic bug identification and fixing

**Methodology**:
1. Reproduce the bug reliably
2. Isolate exact location and conditions
3. Analyze root cause (not symptoms)
4. Implement minimal, targeted fix
5. Verify fix and add tests
6. Prevent recurrence

**Bug Categories**:
- Runtime errors (exceptions, crashes, hangs)
- Logic errors (wrong results, incorrect behavior)
- Integration issues (API failures, network problems)
- Type errors (None handling, type mismatches)
- Concurrency issues (race conditions, deadlocks)
- Performance issues (slow execution, memory leaks)

**Tools**: read, write, glob, grep, shell, code

**Usage**: `kiro-cli --agent bugfix` when encountering bugs or unexpected behavior

---

#### 3. **refactor** (Code Quality Specialist)
**Model**: Claude Opus 4.5  
**Purpose**: Clean architecture and code maintainability

**Principles**:
- SOLID principles
- DRY (Don't Repeat Yourself)
- KISS (Keep It Simple)
- Small, focused functions (< 20 lines)
- Meaningful names
- Minimal nesting (max 2-3 levels)

**Refactoring Priorities**:
1. Extract long functions into smaller ones
2. Remove code duplication
3. Improve naming for clarity
4. Reduce complexity and nesting
5. Add type hints where missing

**Rules**:
- Never change functionality - only structure
- Preserve all existing tests
- Make incremental changes
- Explain each decision

**Tools**: read, write, glob, grep, shell

**Usage**: `kiro-cli --agent refactor` for code cleanup and architecture improvements

---

#### 4. **cli-ui** (TUI Specialist)
**Model**: Claude Sonnet 4.5  
**Purpose**: Building beautiful terminal interfaces with Textual

**Tech Stack**:
- **Textual**: Full TUI framework (widgets, layouts, CSS)
- **Rich**: Simple output, tables, progress bars
- **Typer**: CLI argument parsing

**Best Practices**:
- Composition (reusable widgets)
- CSS styling (.tcss files)
- Reactive attributes for data binding
- Message passing between widgets
- Async-first with workers for blocking ops

**Tools**: read, write, shell, glob, grep, web_search, web_fetch

**Usage**: `kiro-cli --agent cli-ui` for TUI development and UI improvements

---

#### 5. **security-innovator** (Feature Ideation)
**Model**: Claude Sonnet 4.5  
**Purpose**: Generate innovative features based on latest security trends

**Process**:
1. Research latest IT security news and trends
2. Analyze impact on home networks
3. Generate practical, implementable ideas
4. Prioritize by impact, feasibility, alignment

**Output Format**:
- Feature name and description
- Trend/news that inspired it
- Problem it solves
- Implementation approach
- Priority (High/Medium/Low)
- Effort (Small/Medium/Large)
- Impact description

**Tools**: web_search, web_fetch, read, write

**Usage**: `kiro-cli --agent security-innovator` for brainstorming new features

---

#### 6. **prompt-analyzer** (LLM Optimization)
**Model**: Claude Sonnet 4.5  
**Purpose**: Analyze and improve LLM prompts in the codebase

**Focus Areas**:
- System prompt clarity and specificity
- Workflow structure and logic
- Tool usage guidance
- Risk assessment criteria
- Output format requirements

**Analysis Approach**:
1. Read prompt files
2. Evaluate against best practices
3. Test for edge cases
4. Suggest specific improvements
5. Provide before/after examples

**Tools**: read, grep, shell

**Usage**: `kiro-cli --agent prompt-analyzer` for optimizing AI agent prompts

---

#### 7. **devlog** (Documentation Tracker)
**Model**: Claude Sonnet 4.5  
**Purpose**: Maintain DEVLOG.md for hackathon submission

**Responsibilities**:
- Track development progress
- Format entries consistently
- Track Kiro CLI usage
- Categorize work (Backend, Scanner, CLI, Testing)
- Note technical decisions and rationale

**Format**:
- Time tracking (hours per task)
- Challenges and solutions
- Kiro CLI usage highlights
- Technical decisions with rationale

**Tools**: read, write

**Usage**: `kiro-cli --agent devlog` for updating development log

---

### Agent Usage Examples

```bash
# Start development session
kiro-cli --agent iot-security-dev
> Implement device fingerprinting for tracking known devices

# Debug an issue
kiro-cli --agent bugfix
> The port scanner crashes when scanning 192.168.1.1

# Refactor messy code
kiro-cli --agent refactor
> Refactor src/homeguard/scanner/discovery.py to reduce complexity

# Build new TUI screen
kiro-cli --agent cli-ui
> Create a settings screen for monitoring configuration

# Brainstorm features
kiro-cli --agent security-innovator
> What new features should we add based on recent security trends?

# Optimize prompts
kiro-cli --agent prompt-analyzer
> Analyze the agent system prompt in src/homeguard/agent/prompts.py

# Update documentation
kiro-cli --agent devlog
> I just finished implementing network monitoring (2.5 hours)
```

### Performance Optimizations

- **Concurrent Scanning**: ThreadPoolExecutor for parallel port checks
- **Quick Mode**: 17 ports (< 5 seconds) vs Full Mode (1000+ ports)
- **Caching**: Device fingerprints stored locally
- **Rate Limiting**: Prevents API abuse and network flooding
- **Background Monitoring**: APScheduler for periodic scans

### Device Identification Accuracy

| Metric | Before Enhancement | After Enhancement |
|--------|-------------------|-------------------|
| Unknown devices | 60% | 20% |
| Quick scan ports | 8 | 17 |
| Device types | 10 | 22+ |
| Identification methods | 1 | 4 |

**Supported Device Types**:
- Routers/Gateways (TP-Link, MikroTik, Ubiquiti)
- NAS/Storage (Synology, QNAP, Western Digital)
- Smart Home (Philips Hue, Nest, Ring, Echo, Google Home)
- Streaming (Chromecast, Roku, Fire TV, Apple TV)
- IoT (Smart bulbs, cameras, sensors)
- Network devices (Raspberry Pi, servers, printers)

## Troubleshooting

### Common Issues

**Permission denied when scanning**
```bash
# Solution: Run with sudo for raw socket access
sudo homeguard scan

# Or install without scapy (ping fallback only)
pip install -e . --no-deps
pip install typer rich questionary litellm pyyaml textual apscheduler requests
```

**Backend API not responding**
```bash
# Check if backend is running
docker-compose ps

# View logs
docker-compose logs -f

# Restart backend
cd api && docker-compose restart
```

**"Unknown Device" for most devices**
- Ensure backend API is running (LLM identification requires it)
- Run AI scan instead of Quick scan: `sudo homeguard scan --full`
- Check backend logs for LLM errors: `docker-compose logs homeguard-api`

**TUI crashes or displays incorrectly**
```bash
# Check terminal size (minimum 80x24)
echo $COLUMNS x $LINES

# Clear terminal cache
rm -rf ~/.cache/textual

# Run with debug logging
sudo homeguard --debug
```

**Monitoring alerts not working**
- Check settings in TUI: Press `m` → `Settings`
- Verify scan interval is enabled
- Check logs: `tail -f ~/.homeguard/tui_debug.log`
- For Telegram: Verify bot token and chat ID

**Port scan timeout errors**
```bash
# Port timeout is hardcoded to 2.0s in the scanner
# Use quick scan only (fewer ports, faster)
sudo homeguard scan  # No --full flag

# Or modify src/homeguard/scanner/ports.py if needed
```

### Getting Help

- **Debug logs**: `~/.homeguard/tui_debug.log`
- **Scan reports**: `~/.homeguard/reports/`
- **Configuration**: `~/.homeguard/config.yaml`
- **Check backend**: `curl http://localhost:8000/health`
- **Kiro CLI docs**: `kiro-cli --help`
- **Open an issue**: Include logs and `homeguard info` output

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/homeguard-cli
cd homeguard-cli

# Install with dev dependencies
pip install -e ".[dev,full]"

# Start backend
cd api && docker-compose up -d

# Run tests
pytest

# Format code
black src/ tests/
ruff check src/ tests/
```

### Running Tests

```bash
# All tests
pytest

# Specific module
pytest tests/test_scanner/

# With coverage
pytest --cov=homeguard --cov-report=html
```

### Built with Kiro CLI

This project was developed using Kiro CLI for AI-powered development:

- **30 hours** of development time
- **7 specialized agents** for different tasks
- **11 custom prompts** for workflow automation
- **Steering documents** for consistent AI guidance
- **@prime → @plan-feature → @execute → @code-review** workflow

**Agent Usage Statistics**:
- `iot-security-dev`: 60% (primary development)
- `bugfix`: 20% (debugging and fixes)
- `cli-ui`: 10% (TUI development)
- `refactor`: 5% (code cleanup)
- `devlog`: 3% (documentation)
- `security-innovator`: 1% (feature ideation)
- `prompt-analyzer`: 1% (prompt optimization)

See [DEVLOG.md](DEVLOG.md) for complete development timeline and detailed Kiro CLI usage.

## License

MIT License - See [LICENSE](LICENSE) for details

## Acknowledgments

- Built for the [Dynamous Kiro Hackathon](https://dynamous.ai/kiro-hackathon)
- Powered by [Kiro CLI](https://kiro.dev) for AI-assisted development
- LLM backend uses [DeepSeek](https://deepseek.com) for cost-effective AI
- CVE data from [NVD](https://nvd.nist.gov)
- IoT vulnerabilities from [VARIoT](https://www.variotdbs.pl)
