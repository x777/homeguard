# Technical Architecture

## Technology Stack
- **CLI Framework**: Python 3.10+ with Typer + Rich
- **Network Scanning**: Python socket, optionally scapy
- **Backend API**: FastAPI (serverless/managed deployment)
- **LLM Integration**: Backend-proxied (users don't need API keys)
- **Packaging**: PyInstaller for standalone binaries

## Architecture Overview
```
┌──────────────────────────────────────────────────────────┐
│                    LOCAL CLI CLIENT                       │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐              │
│  │ Typer   │───▶│ Scanner │───▶│ JSON    │──────────────┼──┐
│  │ + Rich  │    │ Module  │    │ Packager│              │  │
│  └─────────┘    └─────────┘    └─────────┘              │  │
│       ▲                                                  │  │
│       │         ┌─────────┐                             │  │
│       └─────────│ Renderer│◀─────────────────────────────┼──┤
│                 └─────────┘                             │  │
└──────────────────────────────────────────────────────────┘  │
                                                              │
                         HTTPS/JSON                           │
                                                              ▼
┌──────────────────────────────────────────────────────────┐
│                  BACKEND SERVICE (FastAPI)                │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐              │
│  │ Routes  │───▶│ Analyzer│───▶│ LLM     │              │
│  │         │    │ (CVE)   │    │ Proxy   │              │
│  └─────────┘    └─────────┘    └─────────┘              │
└──────────────────────────────────────────────────────────┘
```

**Two-Component Architecture:**
- **Local CLI**: Scans network, packages results as JSON, sends to backend, renders analysis
- **Backend API**: LLM proxy + CVE analysis (no API keys needed locally)

## LLM Agent Architecture

### Agent Loop
```
┌─────────────────────────────────────────────────────────────┐
│                      AGENT LOOP                              │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Initial  │───▶│   LLM    │───▶│ Decision │              │
│  │  Scan    │    │ Analysis │    │          │              │
│  └──────────┘    └──────────┘    └────┬─────┘              │
│                                       │                     │
│                    ┌──────────────────┼──────────────────┐  │
│                    ▼                  ▼                  ▼  │
│              ┌──────────┐      ┌──────────┐      ┌────────┐│
│              │ Request  │      │ Generate │      │  Done  ││
│              │More Scan │      │  Report  │      │        ││
│              └────┬─────┘      └──────────┘      └────────┘│
│                   │                                        │
│                   ▼                                        │
│              ┌──────────┐                                  │
│              │  User    │ ◀── Approval for sensitive ops   │
│              │ Approval │                                  │
│              └────┬─────┘                                  │
│                   │                                        │
│                   ▼                                        │
│              ┌──────────┐                                  │
│              │ Execute  │───────────────────────┐          │
│              │  Action  │                       │          │
│              └──────────┘                       │          │
│                                                 │          │
│                    ◀────────────────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### LLM Tools (Actions LLM Can Request)
| Tool | Risk Level | Approval |
|------|------------|----------|
| `scan_network` | Low | Auto |
| `scan_ports` | Low | Auto |
| `get_device_info` | Low | Auto |
| `lookup_cve` | Low | Auto |
| `deep_scan_device` | Medium | Ask user |
| `suggest_fix` | Low | Auto (just text) |
| `apply_fix` | High | Always require approval |
| `run_command` | Critical | Always require approval + show command |

### LLM Provider Configuration
```yaml
# ~/.homeguard/config.yaml
llm:
  provider: openai  # openai, anthropic, deepseek, ollama, bedrock
  model: gpt-4
  api_key: ${OPENAI_API_KEY}  # or use backend proxy
  
  # For DeepSeek
  # provider: deepseek
  # model: deepseek-chat
  # api_key: ${DEEPSEEK_API_KEY}
  
  # For local LLM (no internet needed)
  # provider: ollama
  # model: llama3
  # base_url: http://localhost:11434
```

## Development Environment
- Python 3.10+
- pip/poetry for dependency management
- pytest for testing
- black + ruff for formatting/linting

## Code Standards
- PEP 8 style guide
- Type hints for all functions
- Docstrings for public functions/classes
- snake_case for functions/variables, PascalCase for classes

## Testing Strategy
- pytest for unit and integration tests
- Mock network responses for scanner tests
- Test coverage target: 80%+

## Deployment Process
- **CLI**: PyPI package + PyInstaller standalone binaries
- **Backend**: Serverless deployment (AWS Lambda/API Gateway or similar)

## Performance Requirements
- Network scan: < 5 minutes for typical home network
- API response: < 3 seconds for recommendation generation
- CLI startup: < 1 second

## Security Considerations
- No storage of sensitive network data
- API keys stored only on backend (not exposed to users)
- Rate limiting on backend API
- Input validation on all inputs

## Cross-Platform Support
- Windows/macOS/Linux compatibility
- Platform checks with graceful fallbacks when low-level networking is restricted
- Standalone binaries via PyInstaller for each platform
