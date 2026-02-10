#!/usr/bin/env python3
"""BasalGuard — Simple Agent Simulation.

Demonstrates a realistic LLM agent loop using the OpenAI message
structure, but with a **mock LLM** (no API key needed).

The flow mirrors exactly what happens in production:
    1. User sends a message.
    2. LLM responds with ``tool_calls``.
    3. ``ToolExecutor`` processes each call through ``BasalGuardCore``.
    4. Results are appended to the conversation.
    5. LLM (mock) reads results and gives a final answer.

Run::

    PYTHONPATH=src/taipanstack_repo/src:src python3 simple_agent.py

"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Any

# ── Ensure PYTHONPATH ────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
for _p in (
    _ROOT / "src" / "taipanstack_repo" / "src",
    _ROOT / "src",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from basalguard.core.agent_firewall import BasalGuardCore  # noqa: E402
from basalguard.llm_interface.executor import ToolExecutor  # noqa: E402
from basalguard.llm_interface.tool_schemas import BASALGUARD_TOOLS  # noqa: E402


# ── ANSI helpers ─────────────────────────────────────────────────────

class _C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BG_BLU = "\033[44m"
    BG_GRN = "\033[42m"
    BG_MAG = "\033[45m"

    @classmethod
    def disable(cls) -> None:
        for attr in list(vars(cls)):
            if attr.isupper():
                setattr(cls, attr, "")

if not sys.stdout.isatty():
    _C.disable()


def _json(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _print_msg(role: str, content: str, *, colour: str = "") -> None:
    """Print a message in the agent conversation format."""
    icons = {
        "system": f"{_C.DIM}⚙️  SYSTEM",
        "user": f"{_C.CYAN}👤 USER",
        "assistant": f"{_C.MAGENTA}🤖 ASSISTANT",
        "tool": f"{_C.YELLOW}🛡️  TOOL RESULT",
    }
    header = icons.get(role, role)
    print(f"\n  {header}{_C.RESET}")
    print(f"  {'─' * 56}")
    for line in content.split("\n"):
        print(f"  {colour}{line}{_C.RESET}")


def _print_tool_call(name: str, args: dict[str, Any]) -> None:
    """Print a tool call from the mock LLM."""
    print(f"\n  {_C.MAGENTA}🤖 ASSISTANT → tool_call{_C.RESET}")
    print(f"  {'─' * 56}")
    print(f"  {_C.BOLD}Function:{_C.RESET} {_C.YELLOW}{name}{_C.RESET}")
    print(f"  {_C.BOLD}Arguments:{_C.RESET}")
    for line in _json(args).split("\n"):
        print(f"    {_C.DIM}{line}{_C.RESET}")


# ── Mock LLM ────────────────────────────────────────────────────────

class MockLLM:
    """Simulates LLM responses with pre-scripted tool calls.

    In production, this would be replaced by ``openai.chat.completions``
    or ``anthropic.messages.create``.
    """

    def __init__(self) -> None:
        self._step = 0

    def get_response(
        self, messages: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Return the next scripted response.

        Returns:
            A dict mimicking the OpenAI ChatCompletion message format.

        """
        self._step += 1

        # ── Turn 1: LLM decides to create main.py ───────────────────
        if self._step == 1:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_001",
                        "type": "function",
                        "function": {
                            "name": "write_file",
                            "arguments": json.dumps({
                                "path": "main.py",
                                "content": (
                                    '"""Ponto de entrada do projeto."""\n\n'
                                    "\n"
                                    "def main() -> None:\n"
                                    '    """Função principal."""\n'
                                    '    print("Olá Mundo! 🌍")\n'
                                    "\n"
                                    "\n"
                                    'if __name__ == "__main__":\n'
                                    "    main()\n"
                                ),
                            }),
                        },
                    }
                ],
            }

        # ── Turn 2: LLM reads back the file to confirm ──────────────
        if self._step == 2:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_002",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": "main.py"}),
                        },
                    }
                ],
            }

        # ── Turn 3: LLM runs the script ─────────────────────────────
        if self._step == 3:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_003",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": json.dumps({
                                "command_parts": ["python3", "main.py"],
                            }),
                        },
                    }
                ],
            }

        # ── Turn 4: Final answer ────────────────────────────────────
        return {
            "role": "assistant",
            "content": (
                "✅ Pronto! Criei o arquivo `main.py` que imprime "
                '"Olá Mundo! 🌍". O script foi executado com sucesso '
                "dentro do workspace seguro."
            ),
            "tool_calls": None,
        }


# ── Agent Loop ───────────────────────────────────────────────────────

def main() -> None:
    """Run the simulated agent loop."""
    print(f"""
{_C.BOLD}{_C.CYAN}╔══════════════════════════════════════════════════════════════╗
║        🤖  BasalGuard — Simple Agent Simulation  🛡️         ║
║          Mock LLM + Real Firewall + Tool Executor            ║
╚══════════════════════════════════════════════════════════════╝{_C.RESET}
""")

    # ── Setup ────────────────────────────────────────────────────────
    workspace = _ROOT / "agent_workspace"
    firewall = BasalGuardCore(workspace)
    executor = ToolExecutor(firewall)
    llm = MockLLM()

    print(f"  ⚙️  Workspace:  {_C.BOLD}{firewall.workspace_root}{_C.RESET}")
    print(f"  ⚙️  Tools:      {_C.DIM}{[t['function']['name'] for t in BASALGUARD_TOOLS]}{_C.RESET}")
    print(f"  ⚙️  Allowlist:  {_C.DIM}{sorted(firewall.command_allowlist)}{_C.RESET}")

    # ── Conversation ────────────────────────────────────────────────
    system_prompt = (
        "Você é um assistente de programação. Você tem acesso a "
        "ferramentas seguras para criar arquivos e executar comandos "
        "dentro de um workspace protegido pelo BasalGuard."
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Crie um arquivo main.py que imprime Olá Mundo"},
    ]

    _print_msg("system", system_prompt)
    _print_msg("user", messages[-1]["content"])

    # ── Loop ────────────────────────────────────────────────────────
    max_turns = 10
    for turn in range(max_turns):
        response = llm.get_response(messages)
        tool_calls = response.get("tool_calls")

        # If the LLM gave a final text answer, we're done.
        if not tool_calls:
            final_text = response.get("content", "")
            _print_msg("assistant", final_text, colour=_C.GREEN)
            messages.append(response)
            break

        # Process each tool call.
        messages.append(response)

        for call in tool_calls:
            fn = call["function"]
            name = fn["name"]
            args = json.loads(fn["arguments"])

            _print_tool_call(name, args)

            # Execute through BasalGuard
            output = executor.execute_tool_call(name, args)
            result_dict = json.loads(output)

            # Visual feedback
            status = result_dict.get("status", "unknown")
            if status == "success":
                badge = f"{_C.BG_GRN}{_C.BOLD} ✅ PERMITIDO {_C.RESET}"
            else:
                badge = f"{_C.RED}{_C.BOLD} 🛡️  BLOQUEADO {_C.RESET}"

            print(f"\n  {badge}")
            # Show a concise view of the result
            display = {k: v for k, v in result_dict.items() if k != "content"}
            if "content" in result_dict:
                content_preview = result_dict["content"]
                if len(content_preview) > 200:
                    content_preview = content_preview[:200] + "..."
                display["content_preview"] = content_preview
            for line in _json(display).split("\n"):
                print(f"    {_C.DIM}{line}{_C.RESET}")

            # Append tool result to conversation
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": output,
            })

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{_C.BOLD}{_C.WHITE}{'═' * 62}{_C.RESET}")
    print(
        f"  📊 {_C.BOLD}Conversação finalizada{_C.RESET} — "
        f"{len(messages)} mensagens trocadas"
    )

    # Show the file was actually created
    created = workspace / "main.py"
    if created.exists():
        print(
            f"\n  📁 Arquivo criado: {_C.GREEN}{created}{_C.RESET}"
        )
        print(f"  {_C.DIM}{'─' * 56}{_C.RESET}")
        for line in created.read_text(encoding="utf-8").split("\n"):
            print(f"    {_C.DIM}{line}{_C.RESET}")

    print(f"{_C.BOLD}{_C.WHITE}{'═' * 62}{_C.RESET}\n")


if __name__ == "__main__":
    main()
