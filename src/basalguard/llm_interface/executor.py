"""Tool executor — dispatches LLM tool calls to the BasalGuard firewall.

This module provides ``ToolExecutor``, the bridge between the structured
``tool_calls`` that an LLM returns and the secure methods on
``BasalGuardCore``.

Usage::

    from basalguard.core.agent_firewall import BasalGuardCore
    from basalguard.llm_interface.executor import ToolExecutor

    firewall = BasalGuardCore("/tmp/workspace")
    executor = ToolExecutor(firewall)

    # Process a tool call from the LLM
    output = executor.execute_tool_call("write_file", {
        "path": "hello.py",
        "content": "print('Hello!')",
    })
    print(output)  # JSON string the LLM can parse
"""

from __future__ import annotations

import json
import logging
from typing import Any

from basalguard.core.agent_firewall import BasalGuardCore

logger = logging.getLogger("basalguard.executor")

# Map from tool name (as the LLM sees it) → BasalGuard action name.
_TOOL_TO_ACTION: dict[str, str] = {
    "write_file": "write_file",
    "read_file": "read_file",
    "run_command": "execute_command",
}


class ToolExecutor:
    """Dispatch LLM tool calls through the BasalGuard firewall.

    This class is **provider-agnostic** — it only cares about the tool
    name (``str``) and arguments (``dict``), which are the common
    denominator of OpenAI, Anthropic, and other tool-calling APIs.

    Attributes:
        firewall: The ``BasalGuardCore`` instance that enforces security.

    """

    def __init__(self, firewall: BasalGuardCore) -> None:
        """Initialise the executor.

        Args:
            firewall: An already-configured ``BasalGuardCore`` instance.

        """
        self.firewall = firewall

    # ── Public API ───────────────────────────────────────────────────

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str:
        """Execute a single tool call and return the result as JSON.

        This method never raises — all errors are captured and returned
        as a JSON string so the LLM can parse them.

        Args:
            tool_name: The name of the tool the LLM wants to call
                       (e.g. ``"write_file"``, ``"run_command"``).
            arguments: The arguments the LLM passed (already parsed
                       from JSON into a dict).

        Returns:
            A JSON-encoded string with the result dict.  The LLM should
            read the ``"status"`` key to know if the action succeeded,
            was blocked, or errored.

        """
        action = _TOOL_TO_ACTION.get(tool_name)

        if action is None:
            result = {
                "status": "error",
                "reason": (
                    f"Unknown tool '{tool_name}'. "
                    f"Available tools: {sorted(_TOOL_TO_ACTION.keys())}"
                ),
            }
            logger.warning("Unknown tool call: %s", tool_name)
            return self._to_json(result)

        # Translate run_command arguments → validate_intent format.
        params = self._translate_params(action, arguments)
        result = self.firewall.validate_intent(action, params)

        logger.info(
            "Tool %s → %s (status=%s)",
            tool_name,
            action,
            result.get("status"),
        )
        return self._to_json(result)

    def execute_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        """Execute a batch of tool calls (e.g. from OpenAI's response).

        Each tool call dict should have at least::

            {
                "id": "call_abc123",
                "function": {
                    "name": "write_file",
                    "arguments": "{\\"path\\": \\"x.py\\", ...}"
                }
            }

        Args:
            tool_calls: List of tool call dicts from the LLM response.

        Returns:
            A list of tool result messages ready to append to the
            conversation (OpenAI ``role: "tool"`` format).

        """
        results: list[dict[str, str]] = []

        for call in tool_calls:
            call_id = call.get("id", "unknown")
            function = call.get("function", {})
            name = function.get("name", "")
            raw_args = function.get("arguments", "{}")

            # Parse arguments (the LLM sends them as a JSON string).
            try:
                arguments = (
                    json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                )
            except json.JSONDecodeError:
                arguments = {}

            output = self.execute_tool_call(name, arguments)

            results.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": output,
                }
            )

        return results

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _translate_params(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Normalise LLM arguments to BasalGuard's internal format.

        The LLM schema uses ``command_parts`` for run_command, which
        maps to ``command_parts`` in ``validate_intent`` as well; no
        translation needed.  This method exists as an extensibility
        point and for readability.

        """
        # Direct pass-through — the schemas match the firewall's params.
        return dict(arguments)

    @staticmethod
    def _to_json(result: dict[str, Any]) -> str:
        """Serialise a result dict to a compact JSON string."""
        return json.dumps(result, ensure_ascii=False, default=str)

    def __repr__(self) -> str:
        return f"ToolExecutor(firewall={self.firewall!r})"
