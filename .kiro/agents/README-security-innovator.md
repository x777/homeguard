# Security Innovation Agent

## Purpose
Generate innovative feature ideas for HomeGuard CLI based on latest IT security news, trends, and emerging threats.

## Usage

### Switch to the agent:
```bash
/agent swap security-innovator
```

### Or start directly:
```bash
kiro-cli --agent security-innovator
```

### Example prompts:
- "What are the latest home network security threats this month?"
- "Generate 5 feature ideas based on recent IoT vulnerabilities"
- "What security trends should HomeGuard address in 2026?"
- "Research zero-day vulnerabilities affecting home routers"

## What it does
1. **Searches** latest security news from trusted sources
2. **Analyzes** trends relevant to home networks
3. **Generates** practical feature ideas with priority/effort estimates
4. **Documents** ideas in structured format for planning

## Output Format
Each idea includes:
- **Trend/News**: What inspired it
- **Problem**: User pain point
- **Solution**: Implementation approach
- **Priority**: High/Medium/Low
- **Effort**: Small/Medium/Large
- **Impact**: Expected user benefit

## Agent Configuration
- **Model**: Claude Sonnet 4 (best for research + analysis)
- **Tools**: web_search, web_fetch, read, write
- **Context**: Product vision, tech stack, README
- **Focus**: Home networks, CLI/TUI constraints, LLM-driven features
