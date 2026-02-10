#!/usr/bin/env python3
"""BasalGuard — Proof-of-Concept Demo.

Simulates an AI agent loop where a mock LLM emits JSON intents and
BasalGuard deterministically allows or blocks each one.

Run from the project root::

    PYTHONPATH=src/taipanstack_repo/src:src python3 demo_agent_loop.py

"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Any

# ── Ensure PYTHONPATH includes the required source trees ─────────────
_ROOT = Path(__file__).resolve().parent
for _p in (
    _ROOT / "src" / "taipanstack_repo" / "src",  # TaipanStack
    _ROOT / "src",                                 # BasalGuard
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from basalguard.core.agent_firewall import BasalGuardCore  # noqa: E402


# ── ANSI colour helpers (stdlib only) ────────────────────────────────

class _C:
    """Minimal ANSI colour support — gracefully degrades on dumb terms."""

    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BG_RED = "\033[41m"
    BG_GRN = "\033[42m"

    @classmethod
    def disable(cls) -> None:
        for attr in list(vars(cls)):
            if attr.isupper():
                setattr(cls, attr, "")


# Disable colours when piped or on Windows without ANSI support.
if not sys.stdout.isatty():
    _C.disable()


def _pretty_json(obj: Any) -> str:
    """Return a compact, indented JSON string."""
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _print_header() -> None:
    print(f"""
{_C.BOLD}{_C.CYAN}╔══════════════════════════════════════════════════════════════╗
║          🐍  BasalGuard — Agent Firewall Demo  🛡️            ║
║  Prova de Conceito: LLM simulada vs. Firewall determinístico ║
╚══════════════════════════════════════════════════════════════╝{_C.RESET}
""")


def _print_scenario(
    index: int,
    title: str,
    intent: dict[str, Any],
    result: dict[str, Any],
) -> None:
    """Pretty-print one scenario: what the AI tried and BasalGuard's response."""
    status = result.get("status", "unknown")
    is_ok = status == "success"

    # ── Scenario header ──
    colour = _C.GREEN if is_ok else _C.RED
    tag = "LEGÍTIMO" if is_ok else "ATAQUE"
    print(
        f"{_C.BOLD}{_C.WHITE}{'─' * 62}{_C.RESET}\n"
        f"{_C.BOLD}  Cenário {index}  "
        f"{colour}[{tag}]{_C.RESET}  {_C.DIM}{title}{_C.RESET}\n"
        f"{_C.WHITE}{'─' * 62}{_C.RESET}"
    )

    # ── What the AI tried ──
    intent_json = _pretty_json(intent)
    print(
        f"\n  🔴 {_C.YELLOW}IA Tentou:{_C.RESET}\n"
        f"{textwrap.indent(intent_json, '     ')}"
    )

    # ── BasalGuard response ──
    if is_ok:
        badge = f"{_C.BG_GRN}{_C.BOLD} ✅ PERMITIDO {_C.RESET}"
    else:
        badge = f"{_C.BG_RED}{_C.BOLD} 🛡️  BLOQUEADO {_C.RESET}"

    result_json = _pretty_json(result)
    print(
        f"\n  {badge}  {_C.CYAN}BasalGuard Respondeu:{_C.RESET}\n"
        f"{textwrap.indent(result_json, '     ')}\n"
    )


# ── Main demo loop ──────────────────────────────────────────────────

def main() -> None:
    """Run the demo scenarios."""
    _print_header()

    playground = _ROOT / "safe_playground"
    firewall = BasalGuardCore(playground)

    print(
        f"  ⚙️  Workspace: {_C.BOLD}{firewall.workspace_root}{_C.RESET}\n"
        f"  ⚙️  Allowlist: {_C.DIM}{sorted(firewall.command_allowlist)}{_C.RESET}\n"
    )

    # ── Cenários simulados ───────────────────────────────────────────
    scenarios: list[tuple[str, str, dict[str, Any]]] = [
        # ── Cenário 1: ação legítima — criar arquivo de projeto ──
        (
            "Criação legítima de arquivo de projeto",
            "write_file",
            {
                "path": "analise_dados/README.md",
                "content": (
                    "# Análise de Dados\n\n"
                    "Projeto criado pelo agente IA com segurança.\n"
                ),
            },
        ),
        # ── Cenário 2: ataque — path traversal ──
        (
            "Ataque de Path Traversal — tentativa de ler .env",
            "write_file",
            {
                "path": "../../.env",
                "content": "STOLEN_SECRET=exposed",
            },
        ),
        # ── Cenário 3: ataque — command injection ──
        (
            "Ataque de Command Injection — rm -rf disfarçado",
            "execute_command",
            {
                "command_parts": ["ls", "; rm -rf /"],
            },
        ),
        # ── Cenário 4: ação legítima — listar diretório ──
        (
            "Listagem legítima de diretório",
            "execute_command",
            {
                "command_parts": ["ls", "-la"],
            },
        ),
    ]

    blocked_count = 0
    allowed_count = 0

    for i, (title, action, params) in enumerate(scenarios, start=1):
        intent_payload = {"action": action, "params": params}
        result = firewall.validate_intent(action, params)
        _print_scenario(i, title, intent_payload, result)

        if result.get("status") == "success":
            allowed_count += 1
        else:
            blocked_count += 1

    # ── Summary ──────────────────────────────────────────────────────
    print(f"{_C.BOLD}{_C.WHITE}{'═' * 62}{_C.RESET}")
    print(
        f"  📊 {_C.BOLD}Resumo:{_C.RESET}  "
        f"{_C.GREEN}✅ {allowed_count} permitidos{_C.RESET}  │  "
        f"{_C.RED}🛡️  {blocked_count} bloqueados{_C.RESET}"
    )
    print(
        f"\n  {_C.DIM}BasalGuard protegeu o sistema de "
        f"{blocked_count} ação(ões) perigosa(s).{_C.RESET}"
    )
    print(f"{_C.BOLD}{_C.WHITE}{'═' * 62}{_C.RESET}\n")


if __name__ == "__main__":
    main()
