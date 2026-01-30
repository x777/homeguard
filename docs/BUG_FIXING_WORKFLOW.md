# Bug Fixing Workflow

## Overview

HomeGuard includes a specialized bug fixing agent and prompts for systematic debugging and issue resolution.

## Tools Available

### 1. Bug Fix Agent (`bugfix`)
Specialized agent with debugging expertise and systematic methodology.

**Usage:**
```bash
kiro-cli --agent bugfix
```

**Capabilities:**
- Systematic debugging methodology (Reproduce → Isolate → Analyze → Fix → Verify → Prevent)
- Python-specific error analysis
- Network and security tool debugging
- Root cause identification
- Test generation for bug prevention

### 2. Debug Prompt (`@debug`)
Quick debug analysis for immediate error fixing.

**Usage:**
```bash
@debug "AttributeError in loop.py line 245"
@debug src/homeguard/agent/loop.py:245
```

**Best for:**
- Quick error fixes
- Stack trace analysis
- Common Python errors
- Immediate debugging

### 3. Root Cause Analysis (`@rca`)
Comprehensive analysis for GitHub issues.

**Usage:**
```bash
@rca 123  # Analyzes GitHub issue #123
```

**Outputs:**
- Detailed RCA document in `docs/rca/issue-123.md`
- Root cause explanation
- Impact assessment
- Fix proposal
- Testing requirements

### 4. Implement Fix (`@implement-fix`)
Implements the fix from an RCA document.

**Usage:**
```bash
@implement-fix 123  # Implements fix for issue #123
```

### 5. Generate Tests (`@generate-tests`)
Creates unit tests to prevent regressions.

**Usage:**
```bash
@generate-tests src/homeguard/agent/loop.py
@generate-tests _check_port
```

## Workflows

### Quick Bug Fix (< 15 minutes)

For simple errors and exceptions:

```bash
# 1. Use debug prompt
@debug "KeyError: 'device_type' in loop.py"

# 2. Review and apply fix
# (Kiro will show the problem and solution)

# 3. Test the fix
pytest tests/ -v

# 4. Commit
git add .
git commit -m "fix: Handle missing device_type key"
```

### Systematic Bug Fix (GitHub Issue)

For reported issues requiring investigation:

```bash
# 1. Switch to bugfix agent
kiro-cli --agent bugfix

# 2. Run root cause analysis
@rca 123

# 3. Review RCA document
cat docs/rca/issue-123.md

# 4. Implement the fix
@implement-fix 123

# 5. Generate tests to prevent regression
@generate-tests src/homeguard/agent/loop.py

# 6. Run tests
pytest tests/ -v --cov=src/homeguard

# 7. Commit with issue reference
git add .
git commit -m "fix: Handle device_type missing (fixes #123)"
```

### Complex Bug Investigation

For hard-to-reproduce or intermittent bugs:

```bash
# 1. Start bugfix agent
kiro-cli --agent bugfix

# 2. Describe the bug
> I'm seeing intermittent connection timeouts when scanning devices.
> It happens randomly, about 1 in 10 scans.

# 3. Agent will guide you through:
#    - Adding logging
#    - Checking timeouts
#    - Reviewing concurrent operations
#    - Identifying race conditions

# 4. Implement suggested fixes

# 5. Add tests for the edge case
@generate-tests src/homeguard/scanner/ports.py

# 6. Verify fix
pytest tests/ -v -k "timeout"
```

## Debugging Checklist

### Before You Start
- [ ] Can you reproduce the bug?
- [ ] Do you have the error message/stack trace?
- [ ] Do you know which version has the bug?
- [ ] Have you checked recent changes?

### During Investigation
- [ ] Read the error message carefully
- [ ] Check the stack trace
- [ ] Verify your assumptions
- [ ] Add logging at key points
- [ ] Test with minimal input
- [ ] Check for None/empty values
- [ ] Verify types match expectations

### After Fixing
- [ ] Fix tested and working
- [ ] No new errors introduced
- [ ] Tests added for regression prevention
- [ ] Code commented if complex
- [ ] Committed with clear message
- [ ] GitHub issue updated/closed

## Common Bug Patterns in HomeGuard

### 1. Network Errors
**Symptoms:** Timeouts, connection refused, socket errors

**Check:**
- Timeout values (use constants from `constants.py`)
- Error handling for network operations
- Concurrent scan limits
- Firewall/permission issues

**Fix pattern:**
```python
try:
    sock.connect_ex((ip, port))
except socket.error as e:
    logger.warning(f"Connection failed: {e}")
    return None
```

### 2. LLM API Errors
**Symptoms:** JSON decode errors, API failures, rate limits

**Check:**
- Backend URL configuration
- Response format validation
- Timeout handling
- Error response parsing

**Fix pattern:**
```python
try:
    response = httpx.post(url, json=data, timeout=LLM_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()
except httpx.HTTPError as e:
    console.print(f"[red]API error: {e}[/red]")
    return None
```

### 3. Data Validation Errors
**Symptoms:** KeyError, AttributeError, TypeError

**Check:**
- None checks before access
- Dict key existence
- Type assumptions
- Empty list/dict handling

**Fix pattern:**
```python
# Before
device_type = device['device_type'].upper()

# After
device_type = device.get('device_type', 'Unknown').upper()
```

### 4. Concurrency Issues
**Symptoms:** Race conditions, inconsistent state

**Check:**
- Shared state access
- Thread safety
- Async/await usage
- Lock usage

**Fix pattern:**
```python
from threading import Lock

scan_lock = Lock()

def update_scan_data(data):
    with scan_lock:
        # Thread-safe update
        scan_data.update(data)
```

## Tips for Effective Debugging

### 1. Reproduce First
Can't fix what you can't reproduce. Create minimal test case.

### 2. Read the Error
Stack traces tell you exactly where and why. Don't skip them.

### 3. Binary Search
Comment out half the code. Still broken? Bug is in other half.

### 4. Check Recent Changes
`git log` and `git diff` show what changed before bug appeared.

### 5. Add Logging
Strategic print statements reveal execution flow and state.

### 6. Verify Assumptions
Don't assume types, values, or behavior. Print and verify.

### 7. Simplify
Remove complexity until bug disappears, then add back carefully.

### 8. Ask for Help
If stuck > 30 minutes, describe problem to someone (or rubber duck).

## Resources

- **Bug Fix Agent**: `.kiro/agents/bugfix.json`
- **Debug Prompt**: `.kiro/prompts/debug.md`
- **RCA Prompt**: `.kiro/prompts/rca.md`
- **Test Generation**: `.kiro/prompts/generate-tests.md`
- **Implement Fix**: `.kiro/prompts/implement-fix.md`

## Examples

### Example 1: Quick Fix
```bash
$ @debug "AttributeError: 'NoneType' object has no attribute 'get'"

# Kiro identifies the issue:
# Line 245: device_data.get('ip')
# Problem: device_data is None
# Fix: Add None check

# Apply fix:
if device_data is None:
    return None
result = device_data.get('ip')
```

### Example 2: GitHub Issue
```bash
$ @rca 45

# Creates docs/rca/issue-45.md with:
# - Root cause: Missing timeout in HTTP probe
# - Impact: Scans hang indefinitely
# - Fix: Add timeout parameter
# - Tests: Add timeout test case

$ @implement-fix 45
# Implements the fix from RCA

$ @generate-tests src/homeguard/agent/tools/deep_scan.py
# Creates comprehensive tests
```

## Best Practices

1. **Fix root cause, not symptoms** - Don't just catch and ignore errors
2. **Add tests** - Prevent the bug from coming back
3. **Minimal changes** - Fix only what's broken
4. **Document** - Explain why the bug occurred
5. **Verify** - Test the fix thoroughly
6. **Commit clearly** - Reference issue number in commit message

---

**Need help?** Start the bugfix agent and describe your issue:
```bash
kiro-cli --agent bugfix
```
