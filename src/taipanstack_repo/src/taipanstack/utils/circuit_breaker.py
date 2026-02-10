"""
Circuit Breaker pattern implementation.

Provides protection against cascading failures by temporarily
blocking calls to a failing service. Compatible with any
Python framework.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger("taipanstack.utils.circuit_breaker")


class CircuitState(Enum):
    """States of the circuit breaker."""

    CLOSED = "closed"  # Normal operation, requests flow through
    OPEN = "open"  # Circuit is tripped, requests are blocked
    HALF_OPEN = "half_open"  # Testing if service has recovered


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""

    def __init__(self, message: str, state: CircuitState) -> None:
        """Initialize CircuitBreakerError.

        Args:
            message: Error description.
            state: Current circuit state.

        """
        self.state = state
        super().__init__(message)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior.

    Attributes:
        failure_threshold: Number of failures before opening circuit.
        success_threshold: Successes needed in half-open to close.
        timeout: Seconds before trying half-open after open.
        excluded_exceptions: Exceptions that don't count as failures.

    """

    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: float = 30.0
    excluded_exceptions: tuple[type[Exception], ...] = ()


@dataclass
class CircuitBreakerState:
    """Internal state tracking for circuit breaker."""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)


class CircuitBreaker:
    """Circuit breaker implementation.

    Monitors function calls and opens the circuit when too many
    failures occur, preventing further calls until the service
    recovers.

    Example:
        >>> breaker = CircuitBreaker(failure_threshold=3)
        >>> @breaker
        ... def call_external_api():
        ...     return requests.get("https://api.example.com")

    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: float = 30.0,
        excluded_exceptions: tuple[type[Exception], ...] = (),
        name: str = "default",
    ) -> None:
        """Initialize CircuitBreaker.

        Args:
            failure_threshold: Failures before opening circuit.
            success_threshold: Successes to close from half-open.
            timeout: Seconds before attempting half-open.
            excluded_exceptions: Exceptions that don't trip circuit.
            name: Name for logging/identification.

        """
        self.config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            excluded_exceptions=excluded_exceptions,
        )
        self.name = name
        self._state = CircuitBreakerState()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state.state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._state.failure_count

    def _should_attempt(self) -> bool:
        """Check if a call should be attempted."""
        with self._state.lock:
            match self._state.state:
                case CircuitState.CLOSED:
                    return True

                case CircuitState.OPEN:
                    # Check if timeout has passed
                    elapsed = time.monotonic() - self._state.last_failure_time
                    if elapsed >= self.config.timeout:
                        self._state.state = CircuitState.HALF_OPEN
                        self._state.success_count = 0
                        logger.info("Circuit %s entering half-open state", self.name)
                        return True
                    return False

                case CircuitState.HALF_OPEN:
                    # Allow limited attempts
                    return True

    def _record_success(self) -> None:
        """Record a successful call."""
        with self._state.lock:
            match self._state.state:
                case CircuitState.HALF_OPEN:
                    self._state.success_count += 1
                    if self._state.success_count >= self.config.success_threshold:
                        self._state.state = CircuitState.CLOSED
                        self._state.failure_count = 0
                        logger.info("Circuit %s closed after recovery", self.name)

                case CircuitState.CLOSED:
                    # Reset failure count on success
                    self._state.failure_count = 0

                case CircuitState.OPEN:
                    pass  # Should not happen, but handle gracefully

    def _record_failure(self, exc: Exception) -> None:
        """Record a failed call."""
        # Check if exception should be excluded
        if isinstance(exc, self.config.excluded_exceptions):
            return

        with self._state.lock:
            self._state.failure_count += 1
            self._state.last_failure_time = time.monotonic()

            match self._state.state:
                case CircuitState.HALF_OPEN:
                    # Any failure in half-open reopens circuit
                    self._state.state = CircuitState.OPEN
                    logger.warning(
                        "Circuit %s reopened after failure in half-open",
                        self.name,
                    )

                case CircuitState.CLOSED:
                    if self._state.failure_count >= self.config.failure_threshold:
                        self._state.state = CircuitState.OPEN
                        logger.warning(
                            "Circuit %s opened after %d failures",
                            self.name,
                            self._state.failure_count,
                        )

                case CircuitState.OPEN:
                    pass  # Already open, nothing to do

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self._state.lock:
            self._state.state = CircuitState.CLOSED
            self._state.failure_count = 0
            self._state.success_count = 0
            logger.info("Circuit %s manually reset", self.name)

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorate a function with circuit breaker protection."""

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            if not self._should_attempt():
                raise CircuitBreakerError(
                    f"Circuit {self.name} is open",
                    state=self._state.state,
                )

            try:
                result = func(*args, **kwargs)
                self._record_success()
                return result
            except Exception as e:
                self._record_failure(e)
                raise

        return wrapper


def circuit_breaker(
    *,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: float = 30.0,
    excluded_exceptions: tuple[type[Exception], ...] = (),
    name: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to apply circuit breaker pattern.

    Args:
        failure_threshold: Failures before opening circuit.
        success_threshold: Successes to close from half-open.
        timeout: Seconds before attempting half-open.
        excluded_exceptions: Exceptions that don't trip circuit.
        name: Optional name for the circuit.

    Returns:
        Decorated function with circuit breaker protection.

    Example:
        >>> @circuit_breaker(failure_threshold=3, timeout=60)
        ... def call_api(endpoint: str) -> dict:
        ...     return requests.get(endpoint).json()

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            excluded_exceptions=excluded_exceptions,
            name=name or func.__name__,
        )
        return breaker(func)

    return decorator
