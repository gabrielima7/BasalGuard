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

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
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
        assert repr(firewall.workspace_root) in r


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

    def test_blocks_path_traversal_dotdot(self, firewall: BasalGuardCore) -> None:
        """Path with '..' is blocked."""
        result = firewall.safe_write_file("../../etc/passwd", "pwned")
        assert result["status"] == "blocked"
        assert (
            "path_traversal" in result["reason"].lower()
            or "traversal" in result["reason"].lower()
        )

    def test_blocks_path_traversal_encoded(self, firewall: BasalGuardCore) -> None:
        """URL-encoded '..' is also caught."""
        result = firewall.safe_write_file("%2e%2e/secret.key", "pwned")
        assert result["status"] == "blocked"

    def test_blocks_tilde_expansion(self, firewall: BasalGuardCore) -> None:
        """Tilde (~) path is treated as traversal attempt."""
        result = firewall.safe_write_file("~/evil.sh", "rm -rf /")
        assert result["status"] == "blocked"

    def test_sanitises_dangerous_filename(self, firewall: BasalGuardCore) -> None:
        """Dangerous characters in filename are sanitised, not rejected."""
        # Removed ':' to avoid issues with Windows path parsing (drive letters/streams)
        result = firewall.safe_write_file("bad<>name.txt", "safe content")
        assert result["status"] == "success"
        # The written path should NOT contain the dangerous chars
        written_name = Path(result["path"]).name
        assert "<" not in written_name
        assert ">" not in written_name


# ── safe_execute_command ─────────────────────────────────────────────


class TestSafeExecuteCommand:
    """Tests for the safe_execute_command method."""

    def test_allowed_command_succeeds(self, firewall: BasalGuardCore) -> None:
        """An allowlisted command (python) executes successfully."""
        cmd = [sys.executable, "-c", "print('hello')"]
        result = firewall.safe_execute_command(cmd)
        assert result["status"] == "success"
        assert result["returncode"] == 0

    def test_blocks_disallowed_command(self, firewall: BasalGuardCore) -> None:
        """A command not in the allowlist is blocked."""
        result = firewall.safe_execute_command(["curl", "http://evil.com"])
        assert result["status"] == "blocked"
        assert "curl" in result["violator"]

    def test_allows_safe_punctuation_semicolon(self, firewall: BasalGuardCore) -> None:
        """Shell metacharacter (;) is treated as literal arg (shell=False)."""
        # Use python to prove it's treated literally.
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "hello; world"]
        result = firewall.safe_execute_command(cmd)
        assert result["status"] == "success"
        assert "hello; world" in result["stdout"]

    def test_allows_safe_punctuation_pipe(self, firewall: BasalGuardCore) -> None:
        """Pipe (|) is treated as literal arg (shell=False)."""
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "hi | cat"]
        result = firewall.safe_execute_command(cmd)
        assert result["status"] == "success"
        assert "hi | cat" in result["stdout"]

    def test_allows_safe_punctuation_backtick(self, firewall: BasalGuardCore) -> None:
        """Backticks are treated as literal args (shell=False)."""
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "`whoami`"]
        result = firewall.safe_execute_command(cmd)
        assert result["status"] == "success"
        # Verify it did NOT execute whoami (which would output the username)
        # It should output literal backticks
        assert "`whoami`" in result["stdout"]

    def test_blocks_empty_command(self, firewall: BasalGuardCore) -> None:
        """An empty command list is blocked."""
        result = firewall.safe_execute_command([])
        assert result["status"] == "blocked"

    def test_echo_command(self, firewall: BasalGuardCore) -> None:
        """echo is in the default allowlist and works."""
        # Using python as echo replacement for cross-platform compatibility
        cmd = [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "hello from basalguard",
        ]
        result = firewall.safe_execute_command(cmd)
        assert result["status"] == "success"
        assert "hello from basalguard" in result["stdout"]


# ── safe_web_request ─────────────────────────────────────────────────


class TestSafeWebRequest:
    """Tests for the safe_web_request method."""

    @patch("httpx.Client.request")
    def test_successful_get_request(
        self, mock_request: MagicMock, firewall: BasalGuardCore
    ) -> None:
        """A successful GET request returns content."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Hello from the web"
        mock_request.return_value = mock_response

        result = firewall.safe_web_request("http://example.com")
        assert result["status"] == "success"
        assert result["action"] == "web_request"
        assert result["status_code"] == 200
        assert result["content"] == "Hello from the web"
        assert result["url"] == "http://example.com"
        assert result["method"] == "GET"

    def test_unsupported_method(self, firewall: BasalGuardCore) -> None:
        """Only GET and HEAD are allowed."""
        result = firewall.safe_web_request("http://example.com", method="POST")
        assert result["status"] == "blocked"
        assert "not allowed" in result["reason"]

    def test_blocked_url(self, firewall: BasalGuardCore) -> None:
        """Private IPs are blocked by validate_url."""
        result = firewall.safe_web_request("http://127.0.0.1")
        assert result["status"] == "blocked"
        assert result["violator"] == "http://127.0.0.1"

    @patch("httpx.Client.request")
    def test_timeout_exception(
        self, mock_request: MagicMock, firewall: BasalGuardCore
    ) -> None:
        """httpx.TimeoutException is caught and returned as error."""
        mock_request.side_effect = httpx.TimeoutException("timeout")

        result = firewall.safe_web_request("http://example.com")
        assert result["status"] == "error"
        assert "timed out" in result["reason"]
        assert result["violator"] == "http://example.com"

    @patch("httpx.Client.request")
    def test_http_error_exception(
        self, mock_request: MagicMock, firewall: BasalGuardCore
    ) -> None:
        """httpx.HTTPError is caught and returned as error."""
        mock_request.side_effect = httpx.HTTPError("Some HTTP error")

        result = firewall.safe_web_request("http://example.com")
        assert result["status"] == "error"
        assert "HTTP error" in result["reason"]
        assert result["violator"] == "http://example.com"


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

    def test_routes_execute_command(self, firewall: BasalGuardCore) -> None:
        """'execute_command' action is dispatched to safe_execute_command."""
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "dispatched"]
        result = firewall.validate_intent(
            "execute_command",
            {"command_parts": cmd},
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
        result = firewall.validate_intent("write_file", {"content": "no path"})
        assert result["status"] == "error"
        assert "path" in result["reason"].lower()

    def test_missing_content_param(self, firewall: BasalGuardCore) -> None:
        """'write_file' without 'content' returns an error."""
        result = firewall.validate_intent("write_file", {"path": "test.txt"})
        assert result["status"] == "error"

    def test_missing_command_parts(self, firewall: BasalGuardCore) -> None:
        """'execute_command' without 'command_parts' returns an error."""
        result = firewall.validate_intent("execute_command", {})
        assert result["status"] == "error"

    def test_empty_command_parts(self, firewall: BasalGuardCore) -> None:
        """'execute_command' with empty list returns an error."""
        result = firewall.validate_intent("execute_command", {"command_parts": []})
        assert result["status"] == "error"

    def test_traversal_via_intent(self, firewall: BasalGuardCore) -> None:
        """Path traversal via validate_intent is still blocked."""
        result = firewall.validate_intent(
            "write_file",
            {"path": "../../../secret.key", "content": "evil"},
        )
        assert result["status"] == "blocked"

    def test_injection_via_intent_safe(self, firewall: BasalGuardCore) -> None:
        """Command injection attempts are treated as literals via validate_intent."""
        cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", "&& rm -rf /"]
        result = firewall.validate_intent(
            "execute_command",
            {"command_parts": cmd},
        )
        assert result["status"] == "success"
        assert "&& rm -rf /" in result["stdout"]

    @patch.object(BasalGuardCore, "safe_web_request")
    def test_routes_web_request(
        self, mock_safe_web_request: MagicMock, firewall: BasalGuardCore
    ) -> None:
        """'web_request' action is dispatched to safe_web_request."""
        mock_safe_web_request.return_value = {"status": "success"}
        result = firewall.validate_intent(
            "web_request",
            {"url": "http://example.com"},
        )
        assert result["status"] == "success"
        mock_safe_web_request.assert_called_once_with(
            "http://example.com", method="GET"
        )

    def test_missing_url_param(self, firewall: BasalGuardCore) -> None:
        """'web_request' without 'url' returns an error."""
        result = firewall.validate_intent("web_request", {"method": "GET"})
        assert result["status"] == "error"
        assert "url" in result["reason"].lower()


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
