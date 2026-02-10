"""
Retry logic with exponential backoff.

Provides decorators for automatic retry of failing operations
with configurable backoff strategies. Compatible with any
Python framework (sync and async).
"""

from __future__ import annotations

import functools
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger("taipanstack.utils.retry")


@dataclass(frozen=True)
class RetryConfig:
    """Configuration for retry behavior.

    Attributes:
        max_attempts: Maximum number of retry attempts.
        initial_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay between retries.
        exponential_base: Base for exponential backoff (2 = double each time).
        jitter: Whether to add random jitter to delays.
        jitter_factor: Maximum jitter as fraction of delay (0.1 = 10%).

    """

    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_factor: float = 0.1


class RetryError(Exception):
    """Raised when all retry attempts have failed."""

    def __init__(
        self,
        message: str,
        attempts: int,
        last_exception: Exception | None = None,
    ) -> None:
        """Initialize RetryError.

        Args:
            message: Description of the retry failure.
            attempts: Number of attempts made.
            last_exception: The last exception that was raised.

        """
        self.attempts = attempts
        self.last_exception = last_exception
        super().__init__(message)


def calculate_delay(
    attempt: int,
    config: RetryConfig,
) -> float:
    """Calculate delay before next retry.

    Args:
        attempt: Current attempt number (1-indexed).
        config: Retry configuration.

    Returns:
        Delay in seconds before next retry.

    """
    # Exponential backoff
    delay = config.initial_delay * (config.exponential_base ** (attempt - 1))

    # Cap at max delay
    delay = min(delay, config.max_delay)

    # Add jitter if enabled
    # Note: Using random for jitter is intentionally non-cryptographic.
    # Jitter is for load distribution, not security. Using secrets would be overkill.
    if config.jitter:
        jitter_amount = delay * config.jitter_factor
        delay += random.uniform(-jitter_amount, jitter_amount)

    return max(0, delay)


def retry(
    *,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    on: tuple[type[Exception], ...] = (Exception,),
    reraise: bool = True,
    log_retries: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Retry a function with exponential backoff.

    Automatically retries the decorated function when specified
    exceptions are raised, with configurable backoff strategy.

    Args:
        max_attempts: Maximum number of retry attempts.
        initial_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay between retries.
        exponential_base: Base for exponential backoff.
        jitter: Whether to add random jitter to delays.
        on: Exception types to retry on.
        reraise: Whether to reraise the last exception on failure.
        log_retries: Whether to log retry attempts.

    Returns:
        Decorated function with retry logic.

    Example:
        >>> @retry(max_attempts=3, on=(ConnectionError, TimeoutError))
        ... def fetch_data(url: str) -> dict:
        ...     return requests.get(url).json()

    """
    config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
    )

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            last_exception: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except on as e:
                    last_exception = e

                    if attempt == max_attempts:
                        # Last attempt failed
                        if log_retries:
                            logger.warning(
                                "All %d attempts failed for %s: %s",
                                max_attempts,
                                func.__name__,
                                str(e),
                            )
                        break

                    # Calculate delay and wait
                    delay = calculate_delay(attempt, config)

                    if log_retries:
                        logger.info(
                            "Attempt %d/%d failed for %s: %s. "
                            "Retrying in %.2f seconds...",
                            attempt,
                            max_attempts,
                            func.__name__,
                            str(e),
                            delay,
                        )

                    time.sleep(delay)

            # All attempts failed
            if reraise and last_exception is not None:
                raise RetryError(
                    f"All {max_attempts} attempts failed for {func.__name__}",
                    attempts=max_attempts,
                    last_exception=last_exception,
                ) from last_exception

            # Should never reach here if reraise=True
            raise RetryError(
                f"All {max_attempts} attempts failed for {func.__name__}",
                attempts=max_attempts,
                last_exception=last_exception,
            )

        return wrapper

    return decorator


def retry_on_exception(
    exception_types: tuple[type[Exception], ...],
    max_attempts: int = 3,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Retry on specific exceptions.

    A simpler alternative to the full retry decorator when you
    just need basic retry functionality.

    Args:
        exception_types: Exception types to retry on.
        max_attempts: Maximum number of attempts.

    Returns:
        Decorated function with retry logic.

    Example:
        >>> @retry_on_exception((ValueError,), max_attempts=2)
        ... def parse_data(data: str) -> dict:
        ...     return json.loads(data)

    """
    return retry(
        max_attempts=max_attempts,
        on=exception_types,
        jitter=False,
        log_retries=False,
    )


class Retrier:
    """Context manager for retry logic.

    Provides a context manager interface for retry logic when
    decorators are not suitable.

    Example:
        >>> retrier = Retrier(max_attempts=3, on=(ConnectionError,))
        >>> with retrier:
        ...     result = some_operation()

    """

    def __init__(
        self,
        *,
        max_attempts: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        on: tuple[type[Exception], ...] = (Exception,),
    ) -> None:
        """Initialize Retrier.

        Args:
            max_attempts: Maximum retry attempts.
            initial_delay: Initial delay between retries.
            max_delay: Maximum delay between retries.
            on: Exception types to retry on.

        """
        self.config = RetryConfig(
            max_attempts=max_attempts,
            initial_delay=initial_delay,
            max_delay=max_delay,
        )
        self.exception_types = on
        self.attempt = 0
        self.last_exception: Exception | None = None

    def __enter__(self) -> Retrier:
        """Enter the retry context."""
        self.attempt = 0
        self.last_exception = None
        return self

    def __exit__(
        self,
        exc_type: type[Exception] | None,
        exc_val: Exception | None,
        _exc_tb: Any,
    ) -> bool:
        """Exit the retry context.

        Returns True to suppress the exception if we should retry,
        False to let it propagate.
        """
        if exc_type is None:
            return False  # No exception, exit normally

        if not issubclass(exc_type, self.exception_types):
            return False  # Exception type not in retry list

        self.last_exception = exc_val
        self.attempt += 1

        if self.attempt >= self.config.max_attempts:
            return False  # Max attempts reached, propagate exception

        # Calculate delay and wait
        delay = calculate_delay(self.attempt, self.config)
        time.sleep(delay)

        return True  # Suppress exception and retry
