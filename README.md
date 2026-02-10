# BasalGuard 🛡️

**A Deterministic Security Firewall for AI Agents**

BasalGuard acts as a middleware between your AI Agent (LLM) and your operating system. It intercepts all tool calls (file writes, command execution) and validates them against strict security policies *before* execution.

![BasalGuard Demo](https://via.placeholder.com/800x400?text=BasalGuard+Security+Demo)

## Features

- **Path Traversal Protection**: Prevents AI from accessing files outside the designated `safe_workspace`. `../../etc/shadow` attacks are blocked.
- **Command Injection Prevention**: Only allows whitelisted commands (`git`, `python`, `ls`, etc.) and sanitizes arguments.
- **Provider Agnostic**: Works with any OpenAI-compatible API (OpenAI, Groq, OpenRouter, Ollama, LocalAI).
- **Zero-Trust**: Every action is validated. Blocked actions return a structured error to the AI, allowing it to learn and correct itself.

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/zorin/BasalGuard.git
cd BasalGuard

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install openai google-generativeai
```

## Quick Start (Interactive Agent)

The `interactive_agent.py` CLI allows you to chat with an AI model while BasalGuard protects your system.

### 1. Configure your Provider
You can set environment variables for convenience:

**Option A: Groq (Recommended for Speed)**
```bash
export OPENAI_BASE_URL="https://api.groq.com/openai/v1"
export OPENAI_API_KEY="gsk_..."
export OPENAI_MODEL="llama-3.3-70b-versatile"
```

**Option B: OpenRouter**
```bash
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export OPENAI_API_KEY="sk-or-..."
export OPENAI_MODEL="google/gemini-2.0-flash-lite-001"
```

**Option C: OpenAI (Official)**
```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4-turbo"
```

### 2. Run the Agent
```bash
python interactive_agent.py
```
*If environment variables are not set, the script will prompt you for them interactively.*

## Usage Examples

Once inside the interactive session:

**Allowed Action:**
> "Create a file named `hello.txt` with content 'Hello World'"
> *✅ BasalGuard permitiu: {"status": "success", ...}*

**Blocked Action:**
> "Read /etc/passwd"
> *🛡️ BASALGUARD BLOQUEOU: {"status": "blocked", "reason": "Path escapes base directory..."}*

## Project Structure

- `src/basalguard/core/`: The core firewall logic (`BasalGuardCore`).
- `src/basalguard/llm_interface/`: Tool definitions and executor.
- `interactive_agent.py`: The user-facing CLI.
- `safe_workspace/`: The default sandbox directory where the AI operates.

## Security

BasalGuard is designed to be **fail-secure**. If validation fails or an error occurs, the action is blocked by default.

---
*Built with ❤️ by BasalGuard Team*
