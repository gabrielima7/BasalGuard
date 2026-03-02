#!/usr/bin/env python3
"""BasalGuard — Universal Interactive Agent CLI.

A provider-agnostic interface for BasalGuard. works with any OpenAI-compatible API:
- OpenAI (GPT-4, etc.)
- Groq (Llama 3, Mixtral)
- OpenRouter (Any model)
- LocalAI / Ollama / LM Studio

Security:
Every tool call is intercepted and validated by BasalGuardCore.
No API keys are hardcoded in this script.
"""

import json
import os
import sys
from pathlib import Path

# ── Ensure PYTHONPATH ────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
for _p in (
    _ROOT / "src" / "taipanstack_repo" / "src",
    _ROOT / "src",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    from openai import OpenAI
except ImportError:
    print("❌ Erro: Biblioteca 'openai' não instalada.")
    print("Instale com: pip install openai")
    sys.exit(1)


# Imports do BasalGuard (TaipanStack)
from basalguard.core.agent_firewall import BasalGuardCore  # noqa: E402
from basalguard.llm_interface.executor import ToolExecutor  # noqa: E402
from basalguard.llm_interface.tool_schemas import BASALGUARD_TOOLS  # noqa: E402

# Cores para o terminal
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
DIM = "\033[2m"


def _get_input(prompt: str, default: str | None = None, is_secret: bool = False) -> str:
    """Helper for user input with defaults."""
    default_str = f" [{default}]" if default else ""
    value = input(f"{prompt}{DIM}{default_str}{RESET}: ").strip()
    return value if value else (default or "")


def main():
    print(
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}"
    )
    print(f"{BLUE}║    🛡️  BasalGuard — Universal Agent Firewall               ║{RESET}")
    print(
        f"{BLUE}║        Secure AI Execution Environment                     ║{RESET}"
    )
    print(
        f"{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}"
    )

    # 1. Configuração do Provedor (Agnóstico)
    print(f"\n{CYAN}⚙️  Configuração do Provedor de IA{RESET}")

    # Base URL
    default_base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    # Sugestões comuns
    print(f"{DIM}   Exemplos: https://api.groq.com/openai/v1{RESET}")
    print(f"{DIM}             https://openrouter.ai/api/v1{RESET}")
    print(f"{DIM}             http://localhost:11434/v1 (Ollama){RESET}")

    base_url = _get_input("Base URL", default_base_url)

    # API Key
    env_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY")
    api_key = _get_input("API Key", env_key, is_secret=True)
    if not api_key:
        print(
            f"{YELLOW}⚠️  Aviso: Nenhuma API Key fornecida (pode falhar se o provedor exigir auth).{RESET}"
        )

    # Model Name
    default_model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
    model_name = _get_input("Nome do Modelo", default_model)

    # 2. Inicialização do Cliente
    try:
        print(f"\n{DIM}Conectando a {base_url}...{RESET}", end=" ")
        client = OpenAI(base_url=base_url, api_key=api_key)
        # Teste rápido (listar modelos nem sempre funciona em todos proxies, mas é um bom teste)
        # Para ser mais genérico, tentamos listar, se falhar, avisamos mas prosseguimos.
        try:
            client.models.list()
            print(f"{GREEN}OK!{RESET}")
        except Exception:
            print(f"{YELLOW}Aviso (list models falhou, mas continuando...){RESET}")

    except Exception as e:
        print(f"\n{RED}❌ Falha crítica na inicialização do cliente: {e}{RESET}")
        return

    # 3. Inicialização do BasalGuard
    workspace_path = _ROOT / "safe_workspace"
    print(f"🛡️  Inicializando BasalGuard em: {workspace_path}")
    core = BasalGuardCore(workspace_path)
    executor = ToolExecutor(core)

    # 4. System Prompt
    system_prompt = """
    Você é um Engenheiro DevOps Sênior operando dentro de um ambiente seguro chamado BasalGuard.
    
    REGRAS CRÍTICAS DE SEGURANÇA:
    1. Você NÃO PODE executar ações diretas no sistema operacional.
    2. Você DEVE usar as ferramentas fornecidas (`write_file`, `read_file`, `run_command`).
    3. Todas as ações são interceptadas por um firewall. Ações perigosas serão bloqueadas.
    4. Não tente adivinhar o conteúdo de arquivos, use `read_file`.
    5. Seja conciso e técnico.
    """

    messages = [{"role": "system", "content": system_prompt}]

    print(f"\n{YELLOW}💬 Digite 'sair' para encerrar.{RESET}\n")

    # 5. Loop Interativo
    while True:
        try:
            user_input = input(f"{BLUE}Você: {RESET}")
            if user_input.lower() in ["sair", "exit", "quit"]:
                print("👋 Encerrando.")
                break

            if not user_input.strip():
                continue

            messages.append({"role": "user", "content": user_input})

            # Chamada à LLM
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=BASALGUARD_TOOLS,
                tool_choice="auto",
                temperature=0.1,
            )

            msg = response.choices[0].message

            # Se a IA decidiu usar ferramentas
            if msg.tool_calls:
                messages.append(msg)  # Adiciona a intenção da IA ao histórico

                for tool_call in msg.tool_calls:
                    print(f"{YELLOW}🤖 IA solicitou: {tool_call.function.name}{RESET}")

                    # Executa através do BasalGuard
                    tool_name = tool_call.function.name
                    raw_args = tool_call.function.arguments
                    try:
                        args = json.loads(raw_args)

                        # EXECUÇÃO SEGURA 🛡️
                        result = executor.execute_tool_call(tool_name, args)

                        # Verifica se foi bloqueado
                        if (
                            "status" in result and '"blocked"' in result
                        ):  # Simple string check for JSON
                            print(f"{RED}🛡️  BASALGUARD BLOQUEOU: {result}{RESET}")
                        else:
                            # Truncate long output for display
                            display_result = (
                                result[:200] + "..." if len(result) > 200 else result
                            )
                            print(
                                f"{GREEN}✅ BasalGuard permitiu: {display_result}{RESET}"
                            )

                    except Exception as e:
                        result = f"Erro na execução da tool: {str(e)}"
                        print(f"{RED}❌ Erro interno: {result}{RESET}")

                    # Adiciona o resultado ao histórico
                    messages.append(
                        {
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "name": tool_name,
                            "content": result,
                        }
                    )

                # Segunda chamada: IA processa o resultado e responde ao usuário
                final_response = client.chat.completions.create(
                    model=model_name, messages=messages
                )
                final_answer = final_response.choices[0].message.content
                print(f"\n{BLUE}🤖 IA:{RESET} {final_answer}\n")
                messages.append({"role": "assistant", "content": final_answer})

            else:
                # Resposta direta sem tools
                print(f"\n{BLUE}🤖 IA:{RESET} {msg.content}\n")
                messages.append({"role": "assistant", "content": msg.content})

        except KeyboardInterrupt:
            print("\n👋 Interrompido pelo usuário.")
            break
        except Exception as e:
            print(f"{RED}❌ Erro: {e}{RESET}")


if __name__ == "__main__":
    main()
