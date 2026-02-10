"""Unit tests for BasalGuardCore agent firewall.

Covers:
    - Workspace creation
    - Path-traversal blocking
    - Normal file writes
    - Command-injection blocking
    - Allowlist enforcement
    - validate_intent routing & error handling
    - Project-name validation (bonus)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basalguard.core.agent_firewall import (
    BasalGuardCore,
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Return a fresh temporary workspace directory."""
    ws = tmp_path / "ai_workspace"
    return ws  # BasalGuardCore.__init__ will create it


@pytest.fixture
def firewall(workspace: Path) -> BasalGuardCore:
    """Return a BasalGuardCore instance with a temp workspace."""
    return BasalGuardCore(workspace)


# ── Workspace Creation ───────────────────────────────────────────────


class TestWorkspaceCreation:
    """Workspace directory is created on init."""

    def test_creates_workspace_if_missing(self, workspace: Path) -> None:
        """Non-existent workspace dir is created automatically."""
        assert not workspace.exists()
        fw = BasalGuardCore(workspace)
        assert fw.workspace_root.exists()
        assert fw.workspace_root.is_dir()

    def test_existing_workspace_is_fine(self, workspace: Path) -> None:
        """Already-existing workspace doesn't cause an error."""
        workspace.mkdir(parents=True)
        fw = BasalGuardCore(workspace)
        assert fw.workspace_root.exists()

    def test_custom_allowlist(self, workspace: Path) -> None:
        """Custom command allowlist overrides the default."""
        custom = frozenset({"cat"})
        fw = BasalGuardCore(workspace, command_allowlist=custom)
        assert fw.command_allowlist == custom

    def test_repr(self, firewall: BasalGuardCore) -> None:
        """__repr__ includes workspace path and allowlist size."""
        r = repr(firewall)
        assert "BasalGuardCore" in r
        assert str(firewall.workspace_root) in r


# ── safe_write_file ──────────────────────────────────────────────────


class TestSafeWriteFile:
    """Tests for the safe_write_file method."""

    def test_write_simple_file(self, firewall: BasalGuardCore) -> None:
        """A normal file write inside the workspace succeeds."""
        result = firewall.safe_write_file("hello.txt", "Hello, World!")
        assert result["status"] == "success"
        assert result["action"] == "write_file"
        assert result["bytes_written"] == len("Hello, World!".encode("utf-8"))

        written = Path(result["path"])
        assert written.exists()
        assert written.read_text(encoding="utf-8") == "Hello, World!"

    def test_write_nested_path(self, firewall: BasalGuardCore) -> None:
        """Writing to a sub-directory creates parents automatically."""
        result = firewall.safe_write_file("sub/dir/notes.md", "# Notes")
        assert result["status"] == "success"
        assert Path(result["path"]).read_text(encoding="utf-8") == "# Notes"

    def test_blocks_path_traversal_dotdot(
        self, firewall: BasalGuardCore
    ) -> None:
        """Path with '..' is blocked."""
        result = firewall.safe_write_file("../../etc/passwd", "pwned")
        assert result["status"] == "blocked"
        assert "path_traversal" in result["reason"].lower() or "traversal" in result["reason"].lower()

    def test_blocks_path_traversal_encoded(
        self, firewall: BasalGuardCore
    ) -> None:
        """URL-encoded '..' is also caught."""
        result = firewall.safe_write_file("%2e%2e/secret.key", "pwned")
        assert result["status"] == "blocked"

    def test_blocks_tilde_expansion(
        self, firewall: BasalGuardCore
    ) -> None:
        """Tilde (~) path is treated as traversal attempt."""
        result = firewall.safe_write_file("~/evil.sh", "rm -rf /")
        assert result["status"] == "blocked"

    def test_sanitises_dangerous_filename(
        self, firewall: BasalGuardCore
    ) -> None:
        """Dangerous characters in filename are sanitised, not rejected."""
        result = firewall.safe_write_file('bad<>:name.txt', "safe content")
        assert result["status"] == "success"
        # The written path should NOT contain the dangerous chars
        written_name = Path(result["path"]).name
        assert "<" not in written_name
        assert ">" not in written_name
        assert ":" not in written_name


# ── safe_execute_command ─────────────────────────────────────────────


class TestSafeExecuteCommand:
    """Tests for the safe_execute_command method."""

    def test_allowed_command_succeeds(
        self, firewall: BasalGuardCore
    ) -> None:
        """An allowlisted command (ls) executes successfully."""
        result = firewall.safe_execute_command(["ls"])
        assert result["status"] == "success"
        assert result["returncode"] == 0

    def test_blocks_disallowed_command(
        self, firewall: BasalGuardCore
    ) -> None:
        """A command not in the allowlist is blocked."""
        result = firewall.safe_execute_command(["curl", "http://evil.com"])
        assert result["status"] == "blocked"
        assert "curl" in result["violator"]

    def test_blocks_command_injection_semicolon(
        self, firewall: BasalGuardCore
    ) -> None:
        """Shell metacharacter (;) in arguments is blocked."""
        result = firewall.safe_execute_command(["ls", "; rm -rf /"])
        assert result["status"] == "blocked"
        assert "command_injection" in result["reason"].lower() or "dangerous" in result["reason"].lower()

    def test_blocks_command_injection_pipe(
        self, firewall: BasalGuardCore
    ) -> None:
        """Pipe (|) in arguments is blocked."""
        result = firewall.safe_execute_command(["echo", "hi | cat /etc/shadow"])
        assert result["status"] == "blocked"

    def test_blocks_command_injection_backtick(
        self, firewall: BasalGuardCore
    ) -> None:
        """Backtick command substitution is blocked."""
        result = firewall.safe_execute_command(["echo", "`whoami`"])
        assert result["status"] == "blocked"

    def test_blocks_empty_command(
        self, firewall: BasalGuardCore
    ) -> None:
        """An empty command list is blocked."""
        result = firewall.safe_execute_command([])
        assert result["status"] == "blocked"

    def test_echo_command(
        self, firewall: BasalGuardCore
    ) -> None:
        """echo is in the default allowlist and works."""
        result = firewall.safe_execute_command(["echo", "hello from basalguard"])
        assert result["status"] == "success"
        assert "hello from basalguard" in result["stdout"]


# ── validate_intent ──────────────────────────────────────────────────


class TestValidateIntent:
    """Tests for the validate_intent dispatcher."""

    def test_routes_write_file(self, firewall: BasalGuardCore) -> None:
        """'write_file' action is dispatched to safe_write_file."""
        result = firewall.validate_intent(
            "write_file",
            {"path": "intent_test.txt", "content": "routed!"},
        )
        assert result["status"] == "success"
        assert result["action"] == "write_file"

    def test_routes_execute_command(
        self, firewall: BasalGuardCore
    ) -> None:
        """'execute_command' action is dispatched to safe_execute_command."""
        result = firewall.validate_intent(
            "execute_command",
            {"command_parts": ["echo", "dispatched"]},
        )
        assert result["status"] == "success"
        assert "dispatched" in result["stdout"]

    def test_unknown_action(self, firewall: BasalGuardCore) -> None:
        """An unknown action returns an error dict."""
        result = firewall.validate_intent("hack_the_planet", {})
        assert result["status"] == "error"
        assert "Unknown action" in result["reason"]

    def test_missing_path_param(self, firewall: BasalGuardCore) -> None:
        """'write_file' without 'path' returns an error."""
        result = firewall.validate_intent(
            "write_file", {"content": "no path"}
        )
        assert result["status"] == "error"
        assert "path" in result["reason"].lower()

    def test_missing_content_param(self, firewall: BasalGuardCore) -> None:
        """'write_file' without 'content' returns an error."""
        result = firewall.validate_intent(
            "write_file", {"path": "test.txt"}
        )
        assert result["status"] == "error"

    def test_missing_command_parts(self, firewall: BasalGuardCore) -> None:
        """'execute_command' without 'command_parts' returns an error."""
        result = firewall.validate_intent("execute_command", {})
        assert result["status"] == "error"

    def test_empty_command_parts(self, firewall: BasalGuardCore) -> None:
        """'execute_command' with empty list returns an error."""
        result = firewall.validate_intent(
            "execute_command", {"command_parts": []}
        )
        assert result["status"] == "error"

    def test_traversal_via_intent(self, firewall: BasalGuardCore) -> None:
        """Path traversal via validate_intent is still blocked."""
        result = firewall.validate_intent(
            "write_file",
            {"path": "../../../secret.key", "content": "evil"},
        )
        assert result["status"] == "blocked"

    def test_injection_via_intent(self, firewall: BasalGuardCore) -> None:
        """Command injection via validate_intent is still blocked."""
        result = firewall.validate_intent(
            "execute_command",
            {"command_parts": ["ls", "&& rm -rf /"]},
        )
        assert result["status"] == "blocked"


# ── validate_project_name (bonus) ────────────────────────────────────


class TestValidateProjectName:
    """Tests for the static validate_project_name wrapper."""

    def test_valid_name(self) -> None:
        """A valid project name passes."""
        result = BasalGuardCore.validate_project_name("my_cool_project")
        assert result["status"] == "success"
        assert result["validated_name"] == "my_cool_project"

    def test_invalid_name_starts_with_number(self) -> None:
        """A name starting with a digit is rejected."""
        result = BasalGuardCore.validate_project_name("123project")
        assert result["status"] == "blocked"
        assert "violator" in result

    def test_empty_name(self) -> None:
        """An empty name is rejected."""
        result = BasalGuardCore.validate_project_name("")
        assert result["status"] == "blocked"

    def test_reserved_name(self) -> None:
        """A reserved name like 'test' is rejected."""
        result = BasalGuardCore.validate_project_name("test")
        assert result["status"] == "blocked"
