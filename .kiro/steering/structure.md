# Project Structure

## Directory Layout
```
homeguard-cli/
├── src/
│   └── homeguard/
│       ├── __init__.py
│       ├── cli.py              # Typer CLI entry point
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── discovery.py    # Network device discovery
│       │   └── ports.py        # Port scanning
│       ├── client/
│       │   ├── __init__.py
│       │   └── api.py          # Backend API client
│       └── output/
│           ├── __init__.py
│           └── renderer.py     # Rich output formatting
├── api/
│   ├── main.py                 # FastAPI app
│   ├── routes/
│   │   └── analyze.py          # Analysis endpoints
│   ├── services/
│   │   ├── cve.py              # CVE lookup
│   │   └── llm.py              # LLM proxy
│   └── requirements.txt
├── tests/
│   ├── test_scanner/
│   ├── test_client/
│   └── test_api/
├── .kiro/
│   ├── steering/
│   └── prompts/
├── pyproject.toml
├── README.md
├── DEVLOG.md
└── .env.example
```

## File Naming Conventions
- Python files: snake_case.py
- Test files: test_<module>.py
- Config files: lowercase (pyproject.toml, .env)

## Module Organization
- `src/homeguard/`: CLI client package
- `api/`: Backend FastAPI service (separate deployable)
- `tests/`: Mirrors src/api structure

## Configuration Files
- `pyproject.toml`: Project metadata, dependencies
- `.env`: Environment variables
- `.env.example`: Template for required env vars

## Documentation Structure
- `README.md`: Project overview, installation, usage
- `DEVLOG.md`: Development timeline and decisions

## Build Artifacts
- `dist/`: Built packages and PyInstaller binaries
- `.pytest_cache/`: Test cache
