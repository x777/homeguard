---
description: Quick debug analysis for errors and exceptions
argument-hint: [error-description or file:line]
---

# Debug: $ARGUMENTS

## Objective

Quickly analyze and fix the reported error or bug.

## Process

### 1. Understand the Error

**If error message provided:**
- Parse the error type and message
- Identify the stack trace
- Note the failing file and line number

**If file:line provided:**
- Read the code at that location
- Understand the context and purpose
- Check for obvious issues

### 2. Locate the Problem

**Search for the error location:**
```bash
# If error message given, find where it occurs
grep -r "error_message" src/

# If file:line given, read that file
```

**Read the relevant code:**
- Function containing the error
- Surrounding context (10-20 lines before/after)
- Related functions called from there

### 3. Identify Root Cause

**Common Python errors:**

| Error Type | Common Causes | Quick Fixes |
|------------|---------------|-------------|
| `AttributeError: 'NoneType'` | Missing None check | Add `if x is not None:` |
| `KeyError` | Missing dict key | Use `.get()` or check `if key in dict` |
| `IndexError` | List out of bounds | Check `if len(list) > index` |
| `TypeError` | Wrong type passed | Add type validation or conversion |
| `ImportError` | Missing module | Check imports, install dependency |
| `FileNotFoundError` | Wrong path | Verify path exists, use Path() |
| `ConnectionError` | Network issue | Add timeout, retry logic, error handling |
| `JSONDecodeError` | Invalid JSON | Validate JSON before parsing |

**Check for:**
- Missing None/empty checks
- Incorrect type assumptions
- Missing error handling
- Race conditions
- Resource leaks (unclosed files/sockets)
- Off-by-one errors
- Mutable default arguments

### 4. Implement Fix

**Fix principles:**
- Minimal change
- Handle the error properly (don't just catch and ignore)
- Add validation if needed
- Consider edge cases

**Example fixes:**

```python
# Before: AttributeError
result = data['key'].upper()

# After: Safe access
result = data.get('key', '').upper() if data.get('key') else ''

# Before: No error handling
response = httpx.get(url)
data = response.json()

# After: Proper error handling
try:
    response = httpx.get(url, timeout=10.0)
    response.raise_for_status()
    data = response.json()
except httpx.TimeoutException:
    console.print("[red]Request timed out[/red]")
    return None
except httpx.HTTPError as e:
    console.print(f"[red]HTTP error: {e}[/red]")
    return None
except json.JSONDecodeError:
    console.print("[red]Invalid JSON response[/red]")
    return None
```

### 5. Verify Fix

**Test the fix:**
- Run the code that was failing
- Check edge cases
- Ensure no new errors introduced
- Run existing tests if available

```bash
# Run tests
pytest tests/ -v

# Or test specific functionality
python -m homeguard.cli --help
```

### 6. Document

**Add comment explaining the fix:**
```python
# Fix: Handle None case when device data is missing (Issue #123)
if device_data is None:
    return default_device()
```

## Output

Provide:
1. **Root cause**: What was wrong
2. **Fix**: The code change made
3. **Verification**: How to test it works
4. **Prevention**: How to avoid this in future (e.g., add type hints, validation)

## Quick Debug Checklist

- [ ] Error message understood
- [ ] Code location identified
- [ ] Root cause determined
- [ ] Fix implemented
- [ ] Fix tested
- [ ] No side effects
- [ ] Comment added
- [ ] Tests pass

## HomeGuard-Specific Debug Tips

**Network errors:**
- Check timeouts (use constants from `constants.py`)
- Verify IP address format
- Check firewall/permissions

**LLM errors:**
- Check API key/backend URL
- Verify JSON response format
- Handle rate limits

**Scan errors:**
- Check port permissions (need sudo for some ports)
- Verify network interface
- Check concurrent scan limits

**TUI errors:**
- Check Textual version compatibility
- Verify widget state updates
- Check async/await usage

Start by showing the error and the problematic code, then provide the fix.
