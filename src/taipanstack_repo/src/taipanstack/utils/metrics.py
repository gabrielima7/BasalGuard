"""
Metrics collection and monitoring utilities.

Provides lightweight metrics collection for monitoring
application performance and health. Compatible with any
Python framework.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")

logger = logging.getLogger("taipanstack.utils.metrics")


@dataclass
class TimingStats:
    """Statistics for timing measurements."""

    count: int = 0
    total_time: float = 0.0
    min_time: float = float("inf")
    max_time: float = 0.0

    @property
    def avg_time(self) -> float:
        """Calculate average time."""
        return self.total_time / self.count if self.count > 0 else 0.0

    def record(self, duration: float) -> None:
        """Record a timing measurement."""
        self.count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)


@dataclass
class Counter:
    """Simple counter metric."""

    value: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, amount: int = 1) -> int:
        """Increment counter and return new value."""
        with self.lock:
            self.value += amount
            return self.value

    def decrement(self, amount: int = 1) -> int:
        """Decrement counter and return new value."""
        with self.lock:
            self.value -= amount
            return self.value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self.lock:
            self.value = 0


class MetricsCollector:
    """Centralized metrics collection.

    Thread-safe collector for various metric types including
    counters, timers, and gauges.

    Example:
        >>> metrics = MetricsCollector()
        >>> metrics.increment("requests_total")
        >>> with metrics.timer("request_duration"):
        ...     process_request()

    """

    _instance: MetricsCollector | None = None
    _lock = threading.Lock()
    _initialized: bool

    def __new__(cls) -> MetricsCollector:
        """Singleton pattern for global metrics access."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize metrics collector."""
        if self._initialized:
            return

        self._counters: dict[str, Counter] = defaultdict(Counter)
        self._timers: dict[str, TimingStats] = defaultdict(TimingStats)
        self._gauges: dict[str, float] = {}
        self._data_lock = threading.Lock()
        self._initialized = True

    def increment(self, name: str, amount: int = 1) -> int:
        """Increment a counter metric."""
        return self._counters[name].increment(amount)

    def decrement(self, name: str, amount: int = 1) -> int:
        """Decrement a counter metric."""
        return self._counters[name].decrement(amount)

    def gauge(self, name: str, value: float) -> None:
        """Set a gauge metric value."""
        with self._data_lock:
            self._gauges[name] = value

    def get_gauge(self, name: str) -> float | None:
        """Get a gauge metric value."""
        with self._data_lock:
            return self._gauges.get(name)

    def record_time(self, name: str, duration: float) -> None:
        """Record a timing measurement."""
        self._timers[name].record(duration)

    def timer(self, name: str) -> Timer:
        """Create a context manager timer."""
        return Timer(name, self)

    def get_counter(self, name: str) -> int:
        """Get current counter value."""
        return self._counters[name].value

    def get_timer_stats(self, name: str) -> TimingStats | None:
        """Get timing statistics for a named timer."""
        return self._timers.get(name)

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all metrics as a dictionary."""
        with self._data_lock:
            return {
                "counters": {k: v.value for k, v in self._counters.items()},
                "timers": {
                    k: {
                        "count": v.count,
                        "avg": v.avg_time,
                        "min": v.min_time if v.count > 0 else 0,
                        "max": v.max_time,
                        "total": v.total_time,
                    }
                    for k, v in self._timers.items()
                },
                "gauges": dict(self._gauges),
            }

    def reset(self) -> None:
        """Reset all metrics."""
        with self._data_lock:
            self._counters.clear()
            self._timers.clear()
            self._gauges.clear()


class Timer:
    """Context manager for timing code blocks."""

    def __init__(self, name: str, collector: MetricsCollector) -> None:
        """Initialize timer.

        Args:
            name: Name of the timer metric.
            collector: MetricsCollector to record to.

        """
        self.name = name
        self.collector = collector
        self.start_time: float = 0.0

    def __enter__(self) -> Timer:
        """Start the timer."""
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        """Stop timer and record duration."""
        duration = time.perf_counter() - self.start_time
        self.collector.record_time(self.name, duration)


def timed(
    name: str | None = None,
    *,
    collector: MetricsCollector | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to time function execution.

    Args:
        name: Optional metric name (defaults to function name).
        collector: Optional MetricsCollector instance.

    Returns:
        Decorated function that records execution time.

    Example:
        >>> @timed("api_call_duration")
        ... def call_api(endpoint: str) -> dict:
        ...     return requests.get(endpoint).json()

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        metric_name = name or func.__name__
        metrics = collector or MetricsCollector()

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.perf_counter() - start
                metrics.record_time(metric_name, duration)

        return wrapper

    return decorator


def counted(
    name: str | None = None,
    *,
    collector: MetricsCollector | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to count function calls.

    Args:
        name: Optional metric name (defaults to function name).
        collector: Optional MetricsCollector instance.

    Returns:
        Decorated function that counts calls.

    Example:
        >>> @counted("login_attempts")
        ... def login(username: str, password: str) -> bool:
        ...     return authenticate(username, password)

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        metric_name = name or f"{func.__name__}_calls"
        metrics = collector or MetricsCollector()

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            metrics.increment(metric_name)
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Global metrics instance
metrics = MetricsCollector()
