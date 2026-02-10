"""Tests for retry utilities."""

from __future__ import annotations

import pytest

from taipanstack.utils.retry import (
    Retrier,
    RetryConfig,
    RetryError,
    calculate_delay,
    retry,
    retry_on_exception,
)


class TestRetryConfig:
    """Tests for RetryConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = RetryConfig()
        assert config.max_attempts == 3
        assert config.initial_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0
        assert config.jitter is True

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = RetryConfig(
            max_attempts=5,
            initial_delay=0.5,
            max_delay=30.0,
        )
        assert config.max_attempts == 5
        assert config.initial_delay == 0.5
        assert config.max_delay == 30.0

    def test_frozen(self) -> None:
        """Test that config is immutable."""
        config = RetryConfig()
        with pytest.raises(AttributeError):
            config.max_attempts = 10


class TestCalculateDelay:
    """Tests for calculate_delay function."""

    def test_first_attempt_uses_initial_delay(self) -> None:
        """Test that first attempt uses initial delay."""
        config = RetryConfig(initial_delay=1.0, jitter=False)
        delay = calculate_delay(1, config)
        assert delay == 1.0

    def test_exponential_growth(self) -> None:
        """Test exponential backoff growth."""
        config = RetryConfig(
            initial_delay=1.0,
            exponential_base=2.0,
            jitter=False,
        )
        assert calculate_delay(1, config) == 1.0
        assert calculate_delay(2, config) == 2.0
        assert calculate_delay(3, config) == 4.0

    def test_max_delay_capped(self) -> None:
        """Test that delay is capped at max_delay."""
        config = RetryConfig(
            initial_delay=1.0,
            max_delay=5.0,
            jitter=False,
        )
        delay = calculate_delay(10, config)
        assert delay == 5.0

    def test_jitter_adds_randomness(self) -> None:
        """Test that jitter adds randomness."""
        config = RetryConfig(jitter=True, jitter_factor=0.5)

        delays = [calculate_delay(1, config) for _ in range(10)]
        # With 50% jitter, delays should vary
        assert len(set(delays)) > 1


class TestRetryDecorator:
    """Tests for @retry decorator."""

    def test_success_no_retry(self) -> None:
        """Test successful function doesn't retry."""
        call_count = 0

        @retry(max_attempts=3)
        def success_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = success_func()
        assert result == "success"
        assert call_count == 1

    def test_retry_on_failure(self) -> None:
        """Test function retries on failure."""
        call_count = 0

        @retry(max_attempts=3, initial_delay=0.01, on=(ValueError,))
        def failing_then_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "success"

        result = failing_then_success()
        assert result == "success"
        assert call_count == 3

    def test_max_attempts_exceeded(self) -> None:
        """Test RetryError when max attempts exceeded."""

        @retry(max_attempts=2, initial_delay=0.01, on=(ValueError,))
        def always_fail() -> None:
            raise ValueError("Always fails")

        with pytest.raises(RetryError) as exc_info:
            always_fail()
        assert exc_info.value.attempts == 2

    def test_only_catches_specified_exceptions(self) -> None:
        """Test that only specified exceptions trigger retry."""

        @retry(max_attempts=3, on=(ValueError,))
        def raise_type_error() -> None:
            raise TypeError("Wrong type")

        # TypeError should not be caught
        with pytest.raises(TypeError):
            raise_type_error()

    def test_last_exception_preserved(self) -> None:
        """Test that last exception is preserved in RetryError."""

        @retry(max_attempts=2, initial_delay=0.01, on=(ValueError,))
        def failing_func() -> None:
            raise ValueError("Original error")

        with pytest.raises(RetryError) as exc_info:
            failing_func()
        assert exc_info.value.last_exception is not None
        assert "Original error" in str(exc_info.value.last_exception)


class TestRetryOnException:
    """Tests for retry_on_exception decorator."""

    def test_simple_retry(self) -> None:
        """Test simple retry with retry_on_exception."""
        call_count = 0

        @retry_on_exception((ValueError,), max_attempts=2)
        def flaky_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("First fail")
            return "success"

        result = flaky_func()
        assert result == "success"
        assert call_count == 2


class TestRetrier:
    """Tests for Retrier context manager."""

    def test_successful_operation(self) -> None:
        """Test successful operation without retry."""
        retrier = Retrier(max_attempts=3)
        result = None

        with retrier:
            result = "success"

        assert result == "success"
        assert retrier.attempt == 0

    def test_tracks_attempts(self) -> None:
        """Test that retrier tracks attempt count."""
        # With max_attempts=1, exceção propaga na primeira tentativa
        retrier = Retrier(
            max_attempts=1,
            initial_delay=0.01,
            on=(ValueError,),
        )

        # Exception should propagate when max_attempts reached
        with pytest.raises(ValueError):
            with retrier:
                raise ValueError("fail")

        # Attempt was tracked
        assert retrier.attempt == 1

    def test_last_exception_stored(self) -> None:
        """Test that last exception is stored."""
        retrier = Retrier(max_attempts=1, on=(ValueError,))

        with pytest.raises(ValueError):
            with retrier:
                raise ValueError("stored error")

        assert retrier.last_exception is not None


class TestRetryError:
    """Tests for RetryError exception."""

    def test_has_attempts(self) -> None:
        """Test RetryError has attempts count."""
        error = RetryError("Failed", attempts=5)
        assert error.attempts == 5

    def test_has_last_exception(self) -> None:
        """Test RetryError has last exception."""
        original = ValueError("original")
        error = RetryError("Failed", attempts=3, last_exception=original)
        assert error.last_exception is original

    def test_message(self) -> None:
        """Test RetryError message."""
        error = RetryError("All attempts failed", attempts=3)
        assert "All attempts failed" in str(error)
