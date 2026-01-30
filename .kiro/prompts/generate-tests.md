---
description: Generate unit tests for a function or module
argument-hint: [file-path or function-name]
---

# Generate Tests: $ARGUMENTS

## Objective

Create comprehensive unit tests for the specified code to prevent bugs and regressions.

## Process

### 1. Analyze the Code

**Read the target code:**
- Understand what it does
- Identify inputs and outputs
- Note edge cases and error conditions
- Check dependencies

### 2. Identify Test Cases

**Test categories:**

**Happy Path:**
- Normal, expected inputs
- Typical use cases
- Valid data

**Edge Cases:**
- Empty inputs (None, [], {}, "")
- Boundary values (0, -1, max int)
- Single item vs multiple items
- First/last element access

**Error Cases:**
- Invalid inputs
- Wrong types
- Missing required data
- Network failures (if applicable)
- File not found (if applicable)

**Integration:**
- Interaction with other components
- Mock external dependencies

### 3. Write Tests

**Test structure:**
```python
import pytest
from unittest.mock import Mock, patch, MagicMock

def test_function_name_happy_path():
    """Test normal operation with valid inputs."""
    # Arrange
    input_data = ...
    expected = ...
    
    # Act
    result = function_name(input_data)
    
    # Assert
    assert result == expected

def test_function_name_edge_case_empty():
    """Test behavior with empty input."""
    result = function_name([])
    assert result == expected_for_empty

def test_function_name_error_invalid_type():
    """Test error handling for invalid type."""
    with pytest.raises(TypeError):
        function_name("invalid")

def test_function_name_with_mock():
    """Test with mocked dependency."""
    with patch('module.dependency') as mock_dep:
        mock_dep.return_value = "mocked"
        result = function_name()
        assert result == "expected"
        mock_dep.assert_called_once()
```

### 4. Test Naming Convention

**Format:** `test_<function>_<scenario>_<expected>`

**Examples:**
- `test_scan_network_success_returns_devices`
- `test_scan_network_timeout_raises_error`
- `test_scan_network_empty_subnet_returns_empty_list`
- `test_parse_ports_invalid_format_returns_none`

### 5. Coverage Goals

**Aim for:**
- All code paths executed
- All branches tested (if/else)
- All error conditions triggered
- All edge cases covered

**Use pytest-cov to check:**
```bash
pytest tests/ --cov=src/homeguard --cov-report=term-missing
```

### 6. Mock External Dependencies

**Common mocks for HomeGuard:**

```python
# Mock socket operations
@patch('socket.socket')
def test_check_port(mock_socket):
    mock_sock = Mock()
    mock_socket.return_value = mock_sock
    mock_sock.connect_ex.return_value = 0  # Port open
    
    result = _check_port("192.168.1.1", 80)
    assert result is True

# Mock HTTP requests
@patch('httpx.get')
def test_probe_http(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Server": "nginx"}
    mock_get.return_value = mock_response
    
    result = _probe_http("192.168.1.1", 80)
    assert result["server"] == "nginx"

# Mock LLM calls
@patch('homeguard.agent.llm.chat_with_tools')
def test_agent_loop(mock_chat):
    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="test"))]
    mock_chat.return_value = mock_response
    
    run_agent(config)
    mock_chat.assert_called()
```

### 7. Fixtures for Common Setup

```python
@pytest.fixture
def sample_scan_data():
    """Provide sample scan data for tests."""
    return {
        "network": "192.168.1.0/24",
        "devices": [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
        ]
    }

@pytest.fixture
def mock_config():
    """Provide mock LLM config."""
    return LLMConfig(
        provider="backend",
        model="test-model",
        scan_mode="quick"
    )
```

## Test File Structure

**Location:** `tests/test_<module>/test_<file>.py`

**Example for `src/homeguard/agent/loop.py`:**
```
tests/
  test_agent/
    __init__.py
    test_loop.py
```

## Output

Create test file with:
1. **Imports**: All necessary imports and mocks
2. **Fixtures**: Common test data and mocks
3. **Test functions**: Comprehensive test coverage
4. **Docstrings**: Clear description of what each test verifies

## Test Quality Checklist

- [ ] Tests are independent (can run in any order)
- [ ] Tests are fast (< 1 second each)
- [ ] Tests are deterministic (same result every time)
- [ ] Tests have clear names
- [ ] Tests have docstrings
- [ ] Mocks are used for external dependencies
- [ ] Edge cases are covered
- [ ] Error cases are covered
- [ ] Assertions are specific and meaningful

## Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_agent/test_loop.py -v

# Run with coverage
pytest tests/ --cov=src/homeguard --cov-report=html

# Run specific test
pytest tests/test_agent/test_loop.py::test_function_name -v
```

Generate comprehensive tests that catch bugs before they reach production.
