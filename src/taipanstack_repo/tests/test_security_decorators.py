"""Tests for security decorators."""

from __future__ import annotations

import time
import warnings

import pytest

from taipanstack.security.decorators import (
    OperationTimeoutError,
    ValidationError,
    deprecated,
    guard_exceptions,
    require_type,
    timeout,
    validate_inputs,
)
from taipanstack.security.guards import SecurityError


class TestValidateInputs:
    """Tests for @validate_inputs decorator."""

    def test_valid_inputs_pass(self) -> None:
        """Test that valid inputs pass through."""

        def positive_int(x: int) -> int:
            if x <= 0:
                raise ValueError("Must be positive")
            return x

        @validate_inputs(n=positive_int)
        def double(n: int) -> int:
            return n * 2

        assert double(5) == 10

    def test_invalid_input_raises_validation_error(self) -> None:
        """Test that invalid input raises ValidationError."""

        def positive_int(x: int) -> int:
            if x <= 0:
                raise ValueError("Must be positive")
            return x

        @validate_inputs(n=positive_int)
        def double(n: int) -> int:
            return n * 2

        with pytest.raises(ValidationError, match="Must be positive"):
            double(-5)

    def test_validation_error_has_param_name(self) -> None:
        """Test that ValidationError includes parameter name."""

        def always_fail(x: str) -> None:
            raise ValueError("Always fails")

        @validate_inputs(name=always_fail)
        def greet(name: str) -> str:
            return f"Hello {name}"

        with pytest.raises(ValidationError) as exc_info:
            greet("test")
        assert exc_info.value.param_name == "name"

    def test_multiple_validators(self) -> None:
        """Test multiple validators on different params."""

        def min_length(s: str) -> str:
            if len(s) < 3:
                raise ValueError("Too short")
            return s

        def max_value(n: int) -> int:
            if n > 100:
                raise ValueError("Too large")
            return n

        @validate_inputs(name=min_length, age=max_value)
        def register(name: str, age: int) -> dict:
            return {"name": name, "age": age}

        # Valid
        result = register("Alice", 30)
        assert result["name"] == "Alice"

        # Invalid name
        with pytest.raises(ValidationError, match="Too short"):
            register("Al", 30)

        # Invalid age
        with pytest.raises(ValidationError, match="Too large"):
            register("Alice", 150)


class TestGuardExceptions:
    """Tests for @guard_exceptions decorator."""

    def test_no_exception_passes_through(self) -> None:
        """Test that successful execution passes through."""

        @guard_exceptions(catch=(ValueError,))
        def safe_func() -> str:
            return "success"

        assert safe_func() == "success"

    def test_caught_exception_returns_default(self) -> None:
        """Test that caught exception returns default."""

        @guard_exceptions(catch=(ValueError,), default="fallback")
        def failing_func() -> str:
            raise ValueError("error")

        assert failing_func() == "fallback"

    def test_uncaught_exception_propagates(self) -> None:
        """Test that uncaught exceptions propagate."""

        @guard_exceptions(catch=(ValueError,))
        def failing_func() -> str:
            raise TypeError("wrong type")

        with pytest.raises(TypeError):
            failing_func()

    def test_reraise_as_security_error(self) -> None:
        """Test reraising as SecurityError."""

        @guard_exceptions(catch=(IOError,), reraise_as=SecurityError)
        def read_file() -> str:
            raise OSError("file not found")

        with pytest.raises(SecurityError):
            read_file()

    def test_reraise_as_custom_exception(self) -> None:
        """Test reraising as custom exception type."""

        class CustomError(Exception):
            pass

        @guard_exceptions(catch=(ValueError,), reraise_as=CustomError)
        def failing_func() -> str:
            raise ValueError("original")

        with pytest.raises(CustomError):
            failing_func()


class TestTimeout:
    """Tests for @timeout decorator."""

    def test_fast_function_succeeds(self) -> None:
        """Test that fast functions succeed."""

        @timeout(5.0)
        def fast_func() -> str:
            return "done"

        assert fast_func() == "done"

    def test_slow_function_times_out(self) -> None:
        """Test that slow functions time out."""

        @timeout(0.1, use_signal=False)
        def slow_func() -> str:
            time.sleep(1)
            return "done"

        with pytest.raises(OperationTimeoutError):
            slow_func()

    def test_timeout_error_has_details(self) -> None:
        """Test OperationTimeoutError has seconds and func_name."""

        @timeout(0.1, use_signal=False)
        def named_func() -> None:
            time.sleep(1)

        with pytest.raises(OperationTimeoutError) as exc_info:
            named_func()
        assert exc_info.value.seconds == 0.1
        assert exc_info.value.func_name == "named_func"


class TestDeprecated:
    """Tests for @deprecated decorator."""

    def test_emits_deprecation_warning(self) -> None:
        """Test that deprecated function emits warning."""

        @deprecated("Use new_func instead")
        def old_func() -> str:
            return "old"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_func()

        assert result == "old"
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "old_func is deprecated" in str(w[0].message)

    def test_includes_removal_version(self) -> None:
        """Test that removal version is included in warning."""

        @deprecated(removal_version="2.0")
        def old_func() -> None:
            pass

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_func()

        assert "version 2.0" in str(w[0].message)


class TestRequireType:
    """Tests for @require_type decorator."""

    def test_correct_types_pass(self) -> None:
        """Test that correct types pass through."""

        @require_type(name=str, count=int)
        def greet(name: str, count: int) -> str:
            return f"Hello {name}" * count

        assert greet("World", 2) == "Hello WorldHello World"

    def test_wrong_type_raises_type_error(self) -> None:
        """Test that wrong type raises TypeError."""

        @require_type(name=str)
        def greet(name: str) -> str:
            return f"Hello {name}"

        with pytest.raises(TypeError, match="expected str, got int"):
            greet(123)

    def test_multiple_type_checks(self) -> None:
        """Test checking multiple parameters."""

        @require_type(a=int, b=int)
        def add(a: int, b: int) -> int:
            return a + b

        assert add(1, 2) == 3

        with pytest.raises(TypeError):
            add("1", 2)
