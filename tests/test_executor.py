import json
from unittest.mock import MagicMock
import pytest

from basalguard.core.agent_firewall import BasalGuardCore
from basalguard.llm_interface.executor import ToolExecutor

@pytest.fixture
def mock_firewall() -> MagicMock:
    """Return a mocked BasalGuardCore."""
    firewall = MagicMock(spec=BasalGuardCore)
    return firewall

@pytest.fixture
def executor(mock_firewall: MagicMock) -> ToolExecutor:
    """Return a ToolExecutor with a mocked firewall."""
    return ToolExecutor(mock_firewall)

def test_execute_tool_call_known_tool(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test executing a known tool maps to the correct action and calls firewall."""
    # Setup mock return value
    expected_result = {"status": "success", "action": "write_file", "path": "test.txt"}
    mock_firewall.validate_intent.return_value = expected_result

    # Execute
    arguments = {"path": "test.txt", "content": "hello"}
    result_json = executor.execute_tool_call("write_file", arguments)

    # Verify
    mock_firewall.validate_intent.assert_called_once_with("write_file", arguments)

    # Verify JSON output
    result = json.loads(result_json)
    assert result == expected_result

def test_execute_tool_call_unknown_tool(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test executing an unknown tool returns an error and does not call firewall."""
    # Execute
    result_json = executor.execute_tool_call("unknown_tool_xyz", {"arg": "val"})

    # Verify firewall was not called
    mock_firewall.validate_intent.assert_not_called()

    # Verify JSON output has error status
    result = json.loads(result_json)
    assert result["status"] == "error"
    assert "Unknown tool 'unknown_tool_xyz'" in result["reason"]

def test_execute_tool_calls_batch_dict_args(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test executing a batch of tool calls where arguments are dicts."""
    expected_result_1 = {"status": "success", "action": "read_file", "content": "foo"}
    expected_result_2 = {"status": "error", "action": "write_file", "reason": "blocked"}

    mock_firewall.validate_intent.side_effect = [expected_result_1, expected_result_2]

    tool_calls = [
        {
            "id": "call_1",
            "function": {
                "name": "read_file",
                "arguments": {"path": "foo.txt"}
            }
        },
        {
            "id": "call_2",
            "function": {
                "name": "write_file",
                "arguments": {"path": "bar.txt", "content": "baz"}
            }
        }
    ]

    results = executor.execute_tool_calls(tool_calls)

    assert len(results) == 2

    assert results[0]["role"] == "tool"
    assert results[0]["tool_call_id"] == "call_1"
    assert json.loads(results[0]["content"]) == expected_result_1

    assert results[1]["role"] == "tool"
    assert results[1]["tool_call_id"] == "call_2"
    assert json.loads(results[1]["content"]) == expected_result_2

def test_execute_tool_calls_batch_json_args(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test executing a batch of tool calls where arguments are JSON strings."""
    expected_result = {"status": "success", "action": "read_file", "content": "foo"}
    mock_firewall.validate_intent.return_value = expected_result

    tool_calls = [
        {
            "id": "call_1",
            "function": {
                "name": "read_file",
                "arguments": '{"path": "foo.txt"}'
            }
        }
    ]

    results = executor.execute_tool_calls(tool_calls)

    assert len(results) == 1
    mock_firewall.validate_intent.assert_called_once_with("read_file", {"path": "foo.txt"})
    assert json.loads(results[0]["content"]) == expected_result

def test_execute_tool_calls_batch_bad_json_args(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test executing a batch of tool calls where arguments are invalid JSON strings."""
    expected_result = {"status": "success"}
    mock_firewall.validate_intent.return_value = expected_result

    tool_calls = [
        {
            "id": "call_1",
            "function": {
                "name": "read_file",
                "arguments": '{bad_json: true}'
            }
        }
    ]

    results = executor.execute_tool_calls(tool_calls)

    assert len(results) == 1
    # Arguments should default to {}
    mock_firewall.validate_intent.assert_called_once_with("read_file", {})

def test_repr(executor: ToolExecutor, mock_firewall: MagicMock) -> None:
    """Test the __repr__ method of ToolExecutor."""
    r = repr(executor)
    assert r.startswith("ToolExecutor(firewall=")
    assert repr(mock_firewall) in r

def test_translate_params() -> None:
    """Test _translate_params normalises LLM arguments correctly (currently pass-through)."""
    args = {"path": "test.txt", "content": "hello"}
    translated = ToolExecutor._translate_params("write_file", args)

    assert translated == args
    # Ensure it's a new dict
    assert translated is not args
