"""
Security decorators for robust Python applications.

Provides decorators for input validation, exception handling,
timeout control, and other security patterns. Compatible with
any Python framework (Flask, FastAPI, Django, etc.).
"""

from __future__ import annotations

import functools
import signal
import sys
import threading
from collections.abc import Callable, Mapping
from typing import Any, ParamSpec, TypeVar

from taipanstack.security.guards import SecurityError

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


class OperationTimeoutError(Exception):
    """Raised when a function exceeds its timeout limit."""

    def __init__(self, seconds: float, func_name: str = "function") -> None:
        """Initialize OperationTimeoutError.

        Args:
            seconds: The timeout that was exceeded.
            func_name: Name of the function that timed out.

        """
        self.seconds = seconds
        self.func_name = func_name
        super().__init__(f"{func_name} timed out after {seconds} seconds")


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        param_name: str | None = None,
        value: Any = None,
    ) -> None:
        """Initialize ValidationError.

        Args:
            message: Description of the validation failure.
            param_name: Name of the parameter that failed.
            value: The invalid value (sanitized).

        """
        self.param_name = param_name
        self.value = value
        super().__init__(message)


def validate_inputs(
    **validators: Callable[[Any], Any],
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to validate function inputs.

    Validates function arguments using provided validator functions.
    Validators should raise ValueError or ValidationError on invalid input.

    Args:
        **validators: Mapping of parameter names to validator functions.

    Returns:
        Decorated function with input validation.

    Example:
        >>> from taipanstack.security.validators import validate_email, validate_port
        >>> @validate_inputs(email=validate_email, port=validate_port)
        ... def connect(email: str, port: int) -> None:
        ...     pass
        >>> connect(email="invalid", port=8080)
        ValidationError: Invalid email format: invalid

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Get function's parameter names
            import inspect

            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            # Validate each parameter that has a validator
            for param_name, validator in validators.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    try:
                        # Call validator - it should raise on invalid input
                        validated = validator(value)
                        # Update to validated value if returned
                        if validated is not None:
                            bound.arguments[param_name] = validated
                    except (ValueError, TypeError) as e:
                        raise ValidationError(
                            str(e),
                            param_name=param_name,
                            value=repr(value)[:100],
                        ) from e

            # Call original function with validated arguments
            return func(*bound.args, **bound.kwargs)

        return wrapper

    return decorator


def guard_exceptions(
    *,
    catch: tuple[type[Exception], ...] = (Exception,),
    reraise_as: type[Exception] | None = None,
    default: Any = None,
    log_errors: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R | Any]]:
    """Decorator to safely handle exceptions.

    Catches exceptions and optionally re-raises as a different type
    or returns a default value.

    Args:
        catch: Exception types to catch.
        reraise_as: Exception type to re-raise as (None = don't reraise).
        default: Default value to return if exception caught and not reraised.
        log_errors: Whether to log caught exceptions.

    Returns:
        Decorated function with exception handling.

    Example:
        >>> @guard_exceptions(catch=(IOError,), reraise_as=SecurityError)
        ... def read_file(path: str) -> str:
        ...     return open(path).read()
        >>> read_file("/nonexistent")
        SecurityError: [guard_exceptions] ...

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R | Any]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | Any:
            try:
                return func(*args, **kwargs)
            except catch as e:
                if log_errors:
                    import logging

                    logging.getLogger("taipanstack.security").warning(
                        "Exception caught in %s: %s",
                        func.__name__,
                        str(e),
                    )

                if reraise_as is not None:
                    if reraise_as == SecurityError:
                        raise SecurityError(
                            str(e),
                            guard_name="guard_exceptions",
                        ) from e
                    raise reraise_as(str(e)) from e

                return default

        return wrapper

    return decorator


def timeout(
    seconds: float,
    *,
    use_signal: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to limit function execution time.

    Uses signal-based timeout on Unix or thread-based on Windows.
    Signal-based is more reliable but only works in main thread.

    Args:
        seconds: Maximum execution time in seconds.
        use_signal: Use signal-based timeout (Unix only, main thread only).

    Returns:
        Decorated function with timeout.

    Example:
        >>> @timeout(5.0)
        ... def slow_operation() -> str:
        ...     import time
        ...     time.sleep(10)
        ...     return "done"
        >>> slow_operation()
        TimeoutError: slow_operation timed out after 5.0 seconds

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Determine if we can use signals
            can_use_signal = (
                use_signal
                and sys.platform != "win32"
                and threading.current_thread() is threading.main_thread()
            )

            if can_use_signal:
                return _timeout_with_signal(func, seconds, args, kwargs)
            return _timeout_with_thread(func, seconds, args, kwargs)

        return wrapper

    return decorator


def _timeout_with_signal(
    func: Callable[P, R],
    seconds: float,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> R:
    """Implement timeout using Unix signals."""

    def handler(_signum: int, _frame: Any) -> None:
        raise OperationTimeoutError(seconds, func.__name__)

    # Set up signal handler
    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)

    try:
        return func(*args, **kwargs)
    finally:
        # Restore old handler and cancel alarm
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def _timeout_with_thread(
    func: Callable[P, R],
    seconds: float,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> R:
    """Implement timeout using a separate thread."""
    result: list[R] = []
    exception: list[Exception] = []

    def target() -> None:
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            exception.append(e)

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout=seconds)

    if thread.is_alive():
        # Thread still running - timeout occurred
        raise OperationTimeoutError(seconds, func.__name__)

    if exception:
        raise exception[0]

    return result[0]


def deprecated(
    message: str = "",
    *,
    removal_version: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Mark a function as deprecated.

    Emits a warning when the decorated function is called.

    Args:
        message: Additional deprecation message.
        removal_version: Version when function will be removed.

    Returns:
        Decorated function that warns on use.

    Example:
        >>> @deprecated("Use new_function instead", removal_version="2.0")
        ... def old_function() -> None:
        ...     pass

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            import warnings

            msg = f"{func.__name__} is deprecated."
            if removal_version:
                msg += f" Will be removed in version {removal_version}."
            if message:
                msg += f" {message}"

            warnings.warn(msg, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def require_type(
    **type_hints: type,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to enforce runtime type checking.

    Validates that arguments match specified types at runtime.

    Args:
        **type_hints: Mapping of parameter names to expected types.

    Returns:
        Decorated function with type checking.

    Example:
        >>> @require_type(name=str, count=int)
        ... def greet(name: str, count: int) -> None:
        ...     print(f"Hello {name}" * count)
        >>> greet(name=123, count=2)
        TypeError: Parameter 'name' expected str, got int

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            import inspect

            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            for param_name, expected_type in type_hints.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    if not isinstance(value, expected_type):
                        raise TypeError(
                            f"Parameter '{param_name}' expected "
                            f"{expected_type.__name__}, got {type(value).__name__}"
                        )

            return func(*bound.args, **bound.kwargs)

        return wrapper

    return decorator
