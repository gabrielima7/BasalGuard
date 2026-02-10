"""Tests for the Result module (functional error handling)."""

from __future__ import annotations

import pytest

from taipanstack.core.result import (
    Err,
    Ok,
    Result,
    collect_results,
    safe,
    safe_from,
    unwrap_or,
    unwrap_or_else,
)


class TestOkErr:
    """Tests for basic Ok/Err functionality."""

    def test_ok_value(self) -> None:
        """Test Ok wraps value correctly."""
        result: Result[int, Exception] = Ok(42)
        assert result.is_ok()
        assert not result.is_err()
        assert result.ok() == 42

    def test_err_value(self) -> None:
        """Test Err wraps error correctly."""
        error = ValueError("test error")
        result: Result[int, ValueError] = Err(error)
        assert result.is_err()
        assert not result.is_ok()
        assert result.err() == error


class TestSafeDecorator:
    """Tests for the @safe decorator."""

    def test_safe_success(self) -> None:
        """Test safe decorator returns Ok on success."""

        @safe
        def add(a: int, b: int) -> int:
            return a + b

        result = add(2, 3)
        assert result.is_ok()
        assert result.ok() == 5

    def test_safe_exception(self) -> None:
        """Test safe decorator returns Err on exception."""

        @safe
        def divide(a: int, b: int) -> float:
            return a / b

        result = divide(10, 0)
        assert result.is_err()
        assert isinstance(result.err(), ZeroDivisionError)

    def test_safe_preserves_function_metadata(self) -> None:
        """Test safe decorator preserves function name and docstring."""

        @safe
        def my_function() -> int:
            """My docstring."""
            return 42

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


class TestSafeFromDecorator:
    """Tests for the @safe_from decorator."""

    def test_safe_from_catches_specified_exception(self) -> None:
        """Test safe_from catches specified exception types."""

        @safe_from(ValueError)
        def parse(s: str) -> int:
            return int(s)

        result = parse("not_a_number")
        assert result.is_err()
        assert isinstance(result.err(), ValueError)

    def test_safe_from_propagates_unspecified_exception(self) -> None:
        """Test safe_from propagates unspecified exception types."""

        @safe_from(ValueError)
        def divide(a: int, b: int) -> float:
            return a / b

        with pytest.raises(ZeroDivisionError):
            divide(10, 0)

    def test_safe_from_multiple_types(self) -> None:
        """Test safe_from with multiple exception types."""

        @safe_from(ValueError, TypeError)
        def process(x: int | str) -> int:
            if isinstance(x, str):
                return int(x)
            raise TypeError("Expected string")

        result1 = process("abc")
        assert result1.is_err()
        assert isinstance(result1.err(), ValueError)

        result2 = process(123)
        assert result2.is_err()
        assert isinstance(result2.err(), TypeError)


class TestCollectResults:
    """Tests for collect_results function."""

    def test_collect_all_ok(self) -> None:
        """Test collect_results with all Ok values."""
        results: list[Result[int, str]] = [Ok(1), Ok(2), Ok(3)]
        collected = collect_results(results)
        assert collected.is_ok()
        assert collected.ok() == [1, 2, 3]

    def test_collect_with_err(self) -> None:
        """Test collect_results stops at first Err."""
        results: list[Result[int, str]] = [Ok(1), Err("error"), Ok(3)]
        collected = collect_results(results)
        assert collected.is_err()
        assert collected.err() == "error"

    def test_collect_empty(self) -> None:
        """Test collect_results with empty list."""
        results: list[Result[int, str]] = []
        collected = collect_results(results)
        assert collected.is_ok()
        assert collected.ok() == []

    def test_collect_first_err_returned(self) -> None:
        """Test collect_results returns first Err encountered."""
        results: list[Result[int, str]] = [Ok(1), Err("first"), Err("second")]
        collected = collect_results(results)
        assert collected.is_err()
        assert collected.err() == "first"


class TestUnwrapOr:
    """Tests for unwrap_or function."""

    def test_unwrap_or_ok(self) -> None:
        """Test unwrap_or returns Ok value."""
        result: Result[int, str] = Ok(42)
        assert unwrap_or(result, 0) == 42

    def test_unwrap_or_err(self) -> None:
        """Test unwrap_or returns default on Err."""
        result: Result[int, str] = Err("error")
        assert unwrap_or(result, 0) == 0


class TestUnwrapOrElse:
    """Tests for unwrap_or_else function."""

    def test_unwrap_or_else_ok(self) -> None:
        """Test unwrap_or_else returns Ok value."""
        result: Result[int, str] = Ok(42)
        assert unwrap_or_else(result, len) == 42

    def test_unwrap_or_else_err(self) -> None:
        """Test unwrap_or_else computes default from error."""
        result: Result[int, str] = Err("error")
        assert unwrap_or_else(result, len) == 5

    def test_unwrap_or_else_with_exception(self) -> None:
        """Test unwrap_or_else with exception error type."""
        error = ValueError("test message")
        result: Result[int, ValueError] = Err(error)
        assert (
            unwrap_or_else(result, lambda e: len(str(e))) == 12
        )  # len("test message")


class TestMatchCase:
    """Tests for match/case pattern matching with Result."""

    def test_match_ok(self) -> None:
        """Test match/case with Ok value."""
        result: Result[int, str] = Ok(42)
        match result:
            case Ok(value):
                assert value == 42
            case Err():
                pytest.fail("Should not match Err")

    def test_match_err(self) -> None:
        """Test match/case with Err value."""
        result: Result[int, str] = Err("error")
        match result:
            case Ok():
                pytest.fail("Should not match Ok")
            case Err(error):
                assert error == "error"
