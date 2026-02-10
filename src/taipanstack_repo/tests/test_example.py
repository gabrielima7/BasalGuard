"""Example test module for app."""

from src.app.main import greet


def test_greet() -> None:
    """Test the greet function."""
    result = greet("Alice")
    assert result == "Hello, Alice!"
    assert isinstance(result, str)


def test_greet_empty() -> None:
    """Test greet with empty string."""
    result = greet("")
    assert result == "Hello, !"
