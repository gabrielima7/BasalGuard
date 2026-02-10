"""
Result type utilities for functional error handling.

Provides Rust-style Result types (Ok/Err) for explicit error handling,
avoiding exceptions for expected failure cases. This promotes safer,
more predictable code.

Example:
    >>> from taipanstack.core.result import safe, Ok, Err
    >>> @safe
    ... def divide(a: int, b: int) -> float:
    ...     if b == 0:
    ...         raise ValueError("division by zero")
    ...     return a / b
    >>> result = divide(10, 0)
    >>> match result:
    ...     case Err(e):
    ...         print(f"Error: {e}")
    ...     case Ok(value):
    ...         print(f"Result: {value}")
    Error: division by zero

"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable
from typing import ParamSpec, TypeVar

from result import Err, Ok, Result

__all__ = [
    "Err",
    "Ok",
    "Result",
    "collect_results",
    "safe",
    "safe_from",
    "unwrap_or",
    "unwrap_or_else",
]

P = ParamSpec("P")
T = TypeVar("T")
E = TypeVar("E", bound=Exception)
U = TypeVar("U")


def safe(
    func: Callable[P, T],
) -> Callable[P, Result[T, Exception]]:
    """Decorator to convert exceptions into Err results.

    Wraps a function so that any exception raised becomes an Err,
    while successful returns become Ok.

    Args:
        func: The function to wrap.

    Returns:
        A wrapped function that returns Result[T, Exception].

    Example:
        >>> @safe
        ... def parse_int(s: str) -> int:
        ...     return int(s)
        >>> parse_int("42")
        Ok(42)
        >>> parse_int("invalid")
        Err(ValueError("invalid literal for int()..."))

    """

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, Exception]:
        try:
            return Ok(func(*args, **kwargs))
        except Exception as e:
            return Err(e)

    return wrapper


def safe_from(
    *exception_types: type[E],
) -> Callable[[Callable[P, T]], Callable[P, Result[T, E]]]:
    """Decorator factory to catch specific exceptions as Err.

    Only catches specified exception types; others propagate normally.

    Args:
        *exception_types: Exception types to convert to Err.

    Returns:
        Decorator that wraps function with selective error handling.

    Example:
        >>> @safe_from(ValueError, TypeError)
        ... def process(data: str) -> int:
        ...     return int(data)
        >>> process("abc")
        Err(ValueError(...))

    """

    def decorator(func: Callable[P, T]) -> Callable[P, Result[T, E]]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, E]:
            try:
                return Ok(func(*args, **kwargs))
            except exception_types as e:
                return Err(e)

        return wrapper

    return decorator


def collect_results(
    results: Iterable[Result[T, E]],
) -> Result[list[T], E]:
    """Collect an iterable of Results into a single Result.

    If all results are Ok, returns Ok with list of values.
    If any result is Err, returns the first Err encountered.

    Args:
        results: Iterable of Result objects.

    Returns:
        Ok(list[T]) if all are Ok, otherwise first Err.

    Example:
        >>> collect_results([Ok(1), Ok(2), Ok(3)])
        Ok([1, 2, 3])
        >>> collect_results([Ok(1), Err("fail"), Ok(3)])
        Err("fail")

    """
    values: list[T] = []
    for result in results:
        match result:
            case Ok(value):
                values.append(value)
            case Err() as err:
                return err
    return Ok(values)


def unwrap_or(result: Result[T, E], default: T) -> T:
    """Extract value from Result or return default.

    Args:
        result: The Result to unwrap.
        default: Default value if result is Err.

    Returns:
        The Ok value or the default.

    Example:
        >>> unwrap_or(Ok(42), 0)
        42
        >>> unwrap_or(Err("error"), 0)
        0

    """
    match result:
        case Ok(value):
            return value
        case Err():
            return default


def unwrap_or_else(
    result: Result[T, E],
    default_fn: Callable[[E], T],
) -> T:
    """Extract value from Result or compute default from error.

    Args:
        result: The Result to unwrap.
        default_fn: Function to compute default from error.

    Returns:
        The Ok value or computed default.

    Example:
        >>> unwrap_or_else(Ok(42), lambda e: 0)
        42
        >>> unwrap_or_else(Err(ValueError("x")), lambda e: len(str(e)))
        1

    """
    match result:
        case Ok(value):
            return value
        case Err(error):
            return default_fn(error)
