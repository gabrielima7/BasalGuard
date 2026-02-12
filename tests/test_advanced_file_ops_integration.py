import pytest
from pathlib import Path
from basalguard.core.agent_firewall import BasalGuardCore


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def firewall(workspace: Path) -> BasalGuardCore:
    return BasalGuardCore(workspace)


def test_file_ops_integration(firewall: BasalGuardCore, workspace: Path) -> None:
    test_file = workspace / "test.txt"
    test_file.write_text(
        "Hello World\nThis is a test file.\nSecret: 12345\nEnd.", encoding="utf-8"
    )

    # Test search_in_file
    result = firewall.validate_intent(
        "search_in_file", {"path": "test.txt", "pattern": "Secret"}
    )
    assert result["status"] == "success"
    assert len(result["matches"]) == 1
    assert "Secret: 12345" in result["matches"][0]

    # Test read_file_paged
    result = firewall.validate_intent(
        "read_file_paged", {"path": "test.txt", "offset": 0, "limit": 5}
    )
    assert result["status"] == "success"
    assert result["content"] == "Hello"

    # Test read_file_paged offset
    result = firewall.validate_intent(
        "read_file_paged", {"path": "test.txt", "offset": 6, "limit": 5}
    )
    assert result["status"] == "success"
    assert result["content"] == "World"

    # Test large file read via paged (simulated)
    result = firewall.validate_intent(
        "read_file_paged", {"path": "test.txt", "offset": 0, "limit": 1000}
    )
    assert result["status"] == "success"
    assert len(result["content"]) == len(test_file.read_text())


def test_search_in_file_blocked(firewall: BasalGuardCore) -> None:
    # Test path traversal
    result = firewall.validate_intent(
        "search_in_file", {"path": "../../etc/passwd", "pattern": "root"}
    )
    assert result["status"] == "blocked"
    assert "path_traversal" in str(result.get("reason", ""))


def test_read_file_paged_blocked(firewall: BasalGuardCore) -> None:
    # Test path traversal
    result = firewall.validate_intent(
        "read_file_paged", {"path": "../../etc/passwd", "offset": 0}
    )
    assert result["status"] == "blocked"
    assert "path_traversal" in str(result.get("reason", ""))
