"""BasalGuard Agent Firewall — deterministic security layer for AI agents.

This module implements the ``BasalGuardCore`` class, a *logical firewall*
that sits between an LLM and the real world (filesystem, terminal).
Every action requested by the AI passes through deterministic security
checks provided by the **TaipanStack** framework before it is allowed to
execute.

Typical usage::

    firewall = BasalGuardCore("/tmp/ai_workspace")

    # AI wants to write a file
    result = firewall.validate_intent("write_file", {
        "path": "notes.txt",
        "content": "Hello, world!",
    })
    assert result["status"] == "success"

    # AI tries to escape the workspace — blocked deterministically
    result = firewall.validate_intent("write_file", {
        "path": "../../etc/passwd",
        "content": "pwned",
    })
    assert result["status"] == "blocked"
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx

from basalguard.security.network import NetworkSecurityError, validate_url
from taipanstack.security.guards import (
    SecurityError,
    guard_command_injection,
    guard_path_traversal,
)
from taipanstack.security.sanitizers import sanitize_filename
from taipanstack.security.validators import validate_project_name
from taipanstack.utils.subprocess import SafeCommandResult, run_safe_command

logger = logging.getLogger("basalguard.firewall")

# ── Constants ────────────────────────────────────────────────────────────
# Restricted allowlist — the *minimum* a coding agent needs.
# Intentionally paranoid: no curl, wget, nc, dd, etc.
DEFAULT_COMMAND_ALLOWLIST: frozenset[str] = frozenset(
    {
        "git",
        "python",
        "python3",
        "pip",
        "pip3",
        "ls",
        "cat",
        "echo",
        "mkdir",
    }
)

# Maximum file size for reads (1 MiB) — prevents DoS on huge files.
_MAX_READ_SIZE_BYTES: int = 1_048_576

# Maximum response body to keep in memory (50 KiB).
_MAX_RESPONSE_BODY: int = 50 * 1024

# HTTP request timeout in seconds.
_HTTP_TIMEOUT_SECONDS: int = 10

# Actions the firewall understands.
_VALID_ACTIONS: frozenset[str] = frozenset(
    {"write_file", "read_file", "execute_command", "web_request"}
)


class BasalGuardCore:
    """Deterministic security firewall for AI agent actions.

    Every interaction between the LLM and the outside world is mediated
    by this class.  It wraps TaipanStack's security primitives
    (``guard_path_traversal``, ``guard_command_injection``,
    ``sanitize_filename``, ``run_safe_command``) into a high-level API
    that returns **structured dicts** instead of raising exceptions, so
    the LLM can understand *why* an action was blocked.

    Attributes:
        workspace_root: Resolved absolute path to the workspace.
        command_allowlist: Immutable set of allowed base commands.

    """

    # ── Construction ─────────────────────────────────────────────────

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        command_allowlist: frozenset[str] | None = None,
    ) -> None:
        """Initialise the firewall around a workspace directory.

        Args:
            workspace_root: Base directory where the agent may operate.
                            Created automatically if it does not exist.
            command_allowlist: Override the default command allowlist.
                              If ``None``, ``DEFAULT_COMMAND_ALLOWLIST``
                              is used.

        Raises:
            OSError: If the workspace directory cannot be created.

        """
        self.workspace_root: Path = Path(workspace_root).resolve()
        self.command_allowlist: frozenset[str] = (
            command_allowlist
            if command_allowlist is not None
            else DEFAULT_COMMAND_ALLOWLIST
        )

        # Create workspace safely (exist_ok avoids race conditions).
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        logger.info("BasalGuard initialised — workspace: %s", self.workspace_root)

    # ── Safe File Write ──────────────────────────────────────────────

    def safe_write_file(self, path: str, content: str) -> dict[str, Any]:
        """Write a file inside the workspace after security validation.

        Steps:
            1. Sanitise the filename component (remove dangerous chars).
            2. Guard against path-traversal (``..``, symlinks, etc.).
            3. Ensure parent directories exist.
            4. Write the file atomically.

        Args:
            path: Relative (or absolute) file path requested by the AI.
            content: Text content to write.

        Returns:
            A dict with ``"status"`` equal to ``"success"`` or
            ``"blocked"``, plus contextual details.

        """
        try:
            # 1. Sanitise the *filename* part only (keep directory structure).
            file_path = Path(path)
            safe_name = sanitize_filename(file_path.name)
            sanitised_path = (
                str(file_path.parent / safe_name)
                if str(file_path.parent) != "."
                else safe_name
            )

            # 2. Guard: ensure the resolved path stays within workspace.
            resolved = guard_path_traversal(
                sanitised_path,
                base_dir=self.workspace_root,
            )

            # 3. Create parent directories if needed.
            resolved.parent.mkdir(parents=True, exist_ok=True)

            # 4. Write the file.
            resolved.write_text(content, encoding="utf-8")

            logger.info("File written: %s", resolved)
            return {
                "status": "success",
                "action": "write_file",
                "path": str(resolved),
                "bytes_written": len(content.encode("utf-8")),
            }

        except SecurityError as exc:
            logger.warning("BLOCKED write_file — %s (value=%s)", exc, exc.value)
            return {
                "status": "blocked",
                "action": "write_file",
                "reason": str(exc),
                "violator": exc.value or path,
            }
        except (ValueError, OSError) as exc:
            logger.warning("BLOCKED write_file — %s", exc)
            return {
                "status": "blocked",
                "action": "write_file",
                "reason": str(exc),
                "violator": path,
            }

    # ── Safe File Read ────────────────────────────────────────────────

    def safe_read_file(self, path: str) -> dict[str, Any]:
        """Read a file inside the workspace after security validation.

        Steps:
            1. Guard against path-traversal.
            2. Verify the file exists and is not too large.
            3. Read and return the content.

        Args:
            path: Relative (or absolute) file path to read.

        Returns:
            A dict with ``"status"`` equal to ``"success"`` or
            ``"blocked"``, plus ``"content"`` on success.

        """
        try:
            # 1. Guard: ensure the resolved path stays within workspace.
            resolved = guard_path_traversal(
                path,
                base_dir=self.workspace_root,
            )

            # 2. Verify existence.
            if not resolved.exists():
                return {
                    "status": "error",
                    "action": "read_file",
                    "reason": f"File not found: {path}",
                }

            if not resolved.is_file():
                return {
                    "status": "error",
                    "action": "read_file",
                    "reason": f"Path is not a file: {path}",
                }

            # Size check to prevent reading huge files.
            size = resolved.stat().st_size
            if size > _MAX_READ_SIZE_BYTES:
                return {
                    "status": "blocked",
                    "action": "read_file",
                    "reason": (
                        f"File too large ({size} bytes). "
                        f"Max: {_MAX_READ_SIZE_BYTES} bytes."
                    ),
                    "violator": path,
                }

            # 3. Read the file.
            content = resolved.read_text(encoding="utf-8")

            logger.info("File read: %s (%d bytes)", resolved, size)
            return {
                "status": "success",
                "action": "read_file",
                "path": str(resolved),
                "content": content,
                "size_bytes": size,
            }

        except SecurityError as exc:
            logger.warning("BLOCKED read_file — %s (value=%s)", exc, exc.value)
            return {
                "status": "blocked",
                "action": "read_file",
                "reason": str(exc),
                "violator": exc.value or path,
            }
        except (ValueError, OSError) as exc:
            logger.warning("BLOCKED read_file — %s", exc)
            return {
                "status": "blocked",
                "action": "read_file",
                "reason": str(exc),
                "violator": path,
            }

    # ── Safe Command Execution ───────────────────────────────────────

    def safe_execute_command(
        self,
        command_parts: list[str],
    ) -> dict[str, Any]:
        """Execute a shell command after security validation.

        Steps:
            1. Guard against command injection (metacharacters, etc.).
            2. Validate the base command against the allowlist.
            3. Execute via ``run_safe_command`` (no shell=True, ever).

        Args:
            command_parts: The command split into a list of strings,
                           e.g. ``["git", "status"]``.

        Returns:
            A dict with ``"status"`` equal to ``"success"`` or
            ``"blocked"``, plus ``stdout``/``stderr`` on success.

        """
        try:
            # 1-2. Validate injection + allowlist in one step.
            guard_command_injection(
                command_parts,
                allowed_commands=list(self.command_allowlist),
            )

            # 3. Execute the command safely inside the workspace.
            result: SafeCommandResult = run_safe_command(
                command_parts,
                cwd=self.workspace_root,
                allowed_commands=list(self.command_allowlist),
                timeout=60.0,
            )

            logger.info(
                "Command executed: %s (rc=%d)",
                " ".join(command_parts),
                result.returncode,
            )
            return {
                "status": "success",
                "action": "execute_command",
                "command": command_parts,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_seconds": result.duration_seconds,
            }

        except SecurityError as exc:
            logger.warning("BLOCKED execute_command — %s (value=%s)", exc, exc.value)
            return {
                "status": "blocked",
                "action": "execute_command",
                "reason": str(exc),
                "violator": exc.value or (command_parts[0] if command_parts else ""),
            }
        except (ValueError, OSError) as exc:
            logger.warning("BLOCKED execute_command — %s", exc)
            return {
                "status": "blocked",
                "action": "execute_command",
                "reason": str(exc),
                "violator": command_parts[0] if command_parts else "",
            }

    # ── Intent Router (Central Entry-Point) ──────────────────────────

    def validate_intent(
        self,
        action: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate and route an AI agent's intended action.

        This is the **single entry-point** for all agent interactions.
        The LLM sends a JSON-like intent and receives a structured
        response — never an unhandled exception.

        Supported actions:
            - ``"write_file"``:  requires ``params["path"]`` and
              ``params["content"]``.
            - ``"execute_command"``: requires
              ``params["command_parts"]`` (a ``list[str]``).

        Args:
            action: The action name (e.g. ``"write_file"``).
            params: Parameters for the action.

        Returns:
            A dict with at minimum ``{"status": "success"|"blocked"|"error"}``.

        """
        if action not in _VALID_ACTIONS:
            return {
                "status": "error",
                "reason": (
                    f"Unknown action '{action}'. "
                    f"Valid actions: {sorted(_VALID_ACTIONS)}"
                ),
            }

        if action == "write_file":
            path = params.get("path")
            content = params.get("content")
            if not isinstance(path, str) or content is None:
                return {
                    "status": "error",
                    "reason": (
                        "Action 'write_file' requires string 'path' "
                        "and 'content' parameters."
                    ),
                }
            return self.safe_write_file(path, str(content))

        if action == "read_file":
            path = params.get("path")
            if not isinstance(path, str):
                return {
                    "status": "error",
                    "reason": (
                        "Action 'read_file' requires a string 'path' parameter."
                    ),
                }
            return self.safe_read_file(path)

        if action == "execute_command":
            command_parts = params.get("command_parts")
            if not isinstance(command_parts, list) or not command_parts:
                return {
                    "status": "error",
                    "reason": (
                        "Action 'execute_command' requires a non-empty "
                        "'command_parts' list."
                    ),
                }
            return self.safe_execute_command(command_parts)

        # action == "web_request"
        url = params.get("url")
        if not isinstance(url, str) or not url:
            return {
                "status": "error",
                "reason": (
                    "Action 'web_request' requires a non-empty 'url' string parameter."
                ),
            }
        method = params.get("method", "GET")
        return self.safe_web_request(url, method=str(method))

    # ── Safe Web Request ─────────────────────────────────────────────

    def safe_web_request(
        self,
        url: str,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Make a secure HTTP request after SSRF validation.

        Steps:
            1. Validate the URL (block private IPs / SSRF).
            2. Execute the HTTP request with a short timeout.
            3. Truncate the response body to prevent memory abuse.

        Args:
            url: The target URL to request.
            method: HTTP method (GET, POST, etc.).  Defaults to GET.

        Returns:
            A dict with ``"status"`` equal to ``"success"`` or
            ``"blocked"``, plus ``"content"`` on success.

        """
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            return {
                "status": "blocked",
                "action": "web_request",
                "reason": (
                    f"HTTP method '{method}' not allowed. "
                    "Only GET and HEAD are permitted."
                ),
                "violator": method,
            }

        try:
            validated = validate_url(url)
        except NetworkSecurityError as exc:
            logger.warning("BLOCKED web_request — %s", exc)
            return {
                "status": "blocked",
                "action": "web_request",
                "reason": str(exc),
                "violator": url,
            }

        try:
            with httpx.Client(
                timeout=_HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                response = client.request(method, validated)

            body = response.text[:_MAX_RESPONSE_BODY]
            logger.info(
                "web_request %s %s → %d (%d bytes)",
                method,
                validated,
                response.status_code,
                len(body),
            )
            return {
                "status": "success",
                "action": "web_request",
                "url": validated,
                "method": method,
                "status_code": response.status_code,
                "content": body,
            }
        except httpx.TimeoutException:
            return {
                "status": "error",
                "action": "web_request",
                "reason": f"Request timed out after {_HTTP_TIMEOUT_SECONDS}s",
                "violator": url,
            }
        except httpx.HTTPError as exc:
            return {
                "status": "error",
                "action": "web_request",
                "reason": f"HTTP error: {exc}",
                "violator": url,
            }

    # ── Utility: project-name validation (bonus) ─────────────────────

    @staticmethod
    def validate_project_name(name: str) -> dict[str, Any]:
        """Validate a project name using TaipanStack's validator.

        Useful when the AI wants to scaffold a new project.

        Args:
            name: Proposed project name.

        Returns:
            Success or error dict.

        """
        try:
            validated = validate_project_name(name)
            return {
                "status": "success",
                "validated_name": validated,
            }
        except ValueError as exc:
            return {
                "status": "blocked",
                "reason": str(exc),
                "violator": name,
            }

    # ── Dunder helpers ───────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"BasalGuardCore(workspace_root={self.workspace_root!r}, "
            f"allowlist_size={len(self.command_allowlist)})"
        )
