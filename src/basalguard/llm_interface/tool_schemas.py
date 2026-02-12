"""OpenAI / Anthropic-compatible tool schemas for BasalGuard.

This module exports ``BASALGUARD_TOOLS``, a list of tool definitions that
can be passed directly to the ``tools`` parameter of the OpenAI Chat
Completions API or adapted for Anthropic's Tool Use API.

Each schema follows the **OpenAI function-calling** format::

    {
        "type": "function",
        "function": {
            "name": "...",
            "description": "...",
            "parameters": { JSON Schema }
        }
    }

Usage::

    from basalguard.llm_interface.tool_schemas import BASALGUARD_TOOLS

    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        tools=BASALGUARD_TOOLS,
    )
"""

from __future__ import annotations

from typing import Any

# ── Tool: write_file ─────────────────────────────────────────────────

WRITE_FILE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "write_file",
        "description": (
            "Create or overwrite a text file inside the secure workspace. "
            "The path is relative to the workspace root. Parent directories "
            "are created automatically. Dangerous characters in filenames "
            "are sanitised. Path traversal attempts (e.g. '../../etc/passwd') "
            "are BLOCKED by the BasalGuard firewall.\n\n"
            "WHEN TO USE: Whenever you need to create source code, config "
            "files, documentation, or any text artifact inside the project."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Relative path for the file, e.g. 'src/main.py' or "
                        "'docs/README.md'. Must stay within the workspace."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": (
                        "The full text content to write to the file. "
                        "Use UTF-8 encoding."
                    ),
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
}

# ── Tool: read_file ──────────────────────────────────────────────────

READ_FILE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": (
            "Read the contents of a text file inside the secure workspace. "
            "The path is relative to the workspace root. Files larger than "
            "1 MiB are blocked to prevent memory issues. Path traversal "
            "attempts are BLOCKED by the BasalGuard firewall.\n\n"
            "WHEN TO USE: When you need to inspect existing source code, "
            "configuration, or any text file before making changes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Relative path of the file to read, e.g. 'src/main.py'."
                    ),
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
}

# ── Tool: run_command ────────────────────────────────────────────────

RUN_COMMAND_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "run_command",
        "description": (
            "Execute a shell command inside the secure workspace. "
            "The command is validated against an allowlist of safe "
            "programs (git, python, python3, pip, ls, cat, echo, mkdir). "
            "Commands NOT in the allowlist are BLOCKED. Shell metacharacters "
            "(;, |, &, $, `, etc.) in arguments are also BLOCKED to prevent "
            "command injection.\n\n"
            "WHEN TO USE: When you need to run git commands, execute Python "
            "scripts, install packages, or list directory contents.\n\n"
            "IMPORTANT: Pass each argument as a separate element in the "
            "command_parts array. Do NOT use shell syntax like pipes or "
            "redirects — they will be blocked."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command_parts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "The command split into a list of strings. "
                        "First element is the program name, rest are args. "
                        "Example: ['git', 'status'] or ['python3', 'main.py']."
                    ),
                },
            },
            "required": ["command_parts"],
            "additionalProperties": False,
        },
    },
}

# ── Tool: web_request ────────────────────────────────────────────────

WEB_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_request",
        "description": (
            "Make a secure HTTP request to an external URL. "
            "The URL is validated against SSRF attacks — requests to "
            "private/internal IPs (127.0.0.1, 192.168.x.x, 10.x.x.x, "
            "etc.) are BLOCKED by the Network Guard.\n\n"
            "WHEN TO USE: When you need to fetch content from a public "
            "website, read an API response, or check if a URL is "
            "reachable. Only GET and HEAD methods are allowed.\n\n"
            "IMPORTANT: This tool only allows access to public internet "
            "endpoints. Any attempt to access internal network resources "
            "will be blocked."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": (
                        "The full URL to request, e.g. 'https://example.com' "
                        "or 'https://api.github.com/repos/user/repo'."
                    ),
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "HEAD"],
                    "description": (
                        "HTTP method. Defaults to GET. Only GET and HEAD are permitted."
                    ),
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
}

# ── Tool: search_in_file ─────────────────────────────────────────────

SEARCH_IN_FILE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "search_in_file",
        "description": (
            "Search for a text pattern in a file (grep replacement). "
            "Reads the file line by line to support large files. "
            "Path traversal attempts are BLOCKED.\n\n"
            "WHEN TO USE: When you need to find specific strings, definitions, "
            "or TODOs in a file without reading the whole file."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path to the file."},
                "pattern": {
                    "type": "string",
                    "description": "The text pattern to search for.",
                },
                "case_sensitive": {
                    "type": "boolean",
                    "description": "Whether to perform case-sensitive search. Default false.",
                },
            },
            "required": ["path", "pattern"],
            "additionalProperties": False,
        },
    },
}

# ── Tool: read_file_paged ────────────────────────────────────────────

READ_FILE_PAGED_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_file_paged",
        "description": (
            "Read a specific chunk of a file (pagination). "
            "Useful for reading large files (>1MB) without exceeding memory limits. "
            "Reads bytes and decodes with replacement for invalid chars.\n\n"
            "WHEN TO USE: When 'read_file' fails due to size limits, or when "
            "you only need to read a specific part of a file."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path to the file."},
                "offset": {
                    "type": "integer",
                    "description": "Byte offset to start reading from. Default 0.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of bytes to read. Default 2000.",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
}

# ── Exported list ────────────────────────────────────────────────────

BASALGUARD_TOOLS: list[dict[str, Any]] = [
    WRITE_FILE_SCHEMA,
    READ_FILE_SCHEMA,
    RUN_COMMAND_SCHEMA,
    WEB_REQUEST_SCHEMA,
    SEARCH_IN_FILE_SCHEMA,
    READ_FILE_PAGED_SCHEMA,
]
"""All BasalGuard tool schemas, ready for ``tools=`` in an API call."""
