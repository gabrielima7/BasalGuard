"""Tests for metrics module."""

from __future__ import annotations

import time

from taipanstack.utils.metrics import (
    Counter,
    MetricsCollector,
    TimingStats,
    counted,
    timed,
)


class TestCounter:
    """Tests for Counter class."""

    def test_starts_at_zero(self) -> None:
        """Test counter starts at zero."""
        counter = Counter()
        assert counter.value == 0

    def test_increment(self) -> None:
        """Test incrementing counter."""
        counter = Counter()
        counter.increment()
        assert counter.value == 1

    def test_increment_by_amount(self) -> None:
        """Test incrementing by specific amount."""
        counter = Counter()
        counter.increment(5)
        assert counter.value == 5

    def test_decrement(self) -> None:
        """Test decrementing counter."""
        counter = Counter()
        counter.increment(10)
        counter.decrement(3)
        assert counter.value == 7

    def test_reset(self) -> None:
        """Test resetting counter."""
        counter = Counter()
        counter.increment(10)
        counter.reset()
        assert counter.value == 0


class TestTimingStats:
    """Tests for TimingStats class."""

    def test_initial_values(self) -> None:
        """Test initial values."""
        stats = TimingStats()
        assert stats.count == 0
        assert stats.total_time == 0.0
        assert stats.avg_time == 0.0

    def test_record_updates_stats(self) -> None:
        """Test recording updates stats."""
        stats = TimingStats()
        stats.record(1.0)
        stats.record(2.0)
        stats.record(3.0)

        assert stats.count == 3
        assert stats.total_time == 6.0
        assert stats.avg_time == 2.0
        assert stats.min_time == 1.0
        assert stats.max_time == 3.0


class TestMetricsCollector:
    """Tests for MetricsCollector class."""

    def test_increment_counter(self) -> None:
        """Test incrementing counter."""
        # Create fresh instance for test
        collector = MetricsCollector()
        collector.reset()

        collector.increment("test_counter")
        assert collector.get_counter("test_counter") == 1

    def test_decrement_counter(self) -> None:
        """Test decrementing counter."""
        collector = MetricsCollector()
        collector.reset()

        collector.increment("test_counter", 10)
        collector.decrement("test_counter", 3)
        assert collector.get_counter("test_counter") == 7

    def test_gauge(self) -> None:
        """Test setting gauge value."""
        collector = MetricsCollector()
        collector.reset()

        collector.gauge("memory_usage", 123.45)
        assert collector.get_gauge("memory_usage") == 123.45

    def test_record_time(self) -> None:
        """Test recording timing."""
        collector = MetricsCollector()
        collector.reset()

        collector.record_time("operation", 0.5)
        stats = collector.get_timer_stats("operation")

        assert stats is not None
        assert stats.count == 1
        assert stats.total_time == 0.5

    def test_timer_context_manager(self) -> None:
        """Test timer context manager."""
        collector = MetricsCollector()
        collector.reset()

        with collector.timer("timed_op"):
            time.sleep(0.01)

        stats = collector.get_timer_stats("timed_op")
        assert stats is not None
        assert stats.count == 1
        assert stats.total_time >= 0.01

    def test_get_all_metrics(self) -> None:
        """Test getting all metrics."""
        collector = MetricsCollector()
        collector.reset()

        collector.increment("requests")
        collector.gauge("cpu", 50.0)
        collector.record_time("latency", 0.1)

        all_metrics = collector.get_all_metrics()

        assert "counters" in all_metrics
        assert "gauges" in all_metrics
        assert "timers" in all_metrics
        assert all_metrics["counters"]["requests"] == 1
        assert all_metrics["gauges"]["cpu"] == 50.0

    def test_reset(self) -> None:
        """Test resetting all metrics."""
        collector = MetricsCollector()

        collector.increment("test")
        collector.gauge("test", 1.0)
        collector.reset()

        assert collector.get_counter("test") == 0
        assert collector.get_gauge("test") is None


class TestTimedDecorator:
    """Tests for @timed decorator."""

    def test_times_function(self) -> None:
        """Test that function is timed."""
        collector = MetricsCollector()
        collector.reset()

        @timed("my_func", collector=collector)
        def slow_func() -> str:
            time.sleep(0.01)
            return "done"

        result = slow_func()

        assert result == "done"
        stats = collector.get_timer_stats("my_func")
        assert stats is not None
        assert stats.count == 1

    def test_default_name(self) -> None:
        """Test that default name is function name."""
        collector = MetricsCollector()
        collector.reset()

        @timed(collector=collector)
        def named_function() -> None:
            pass

        named_function()

        stats = collector.get_timer_stats("named_function")
        assert stats is not None


class TestCountedDecorator:
    """Tests for @counted decorator."""

    def test_counts_calls(self) -> None:
        """Test that calls are counted."""
        collector = MetricsCollector()
        collector.reset()

        @counted("my_counter", collector=collector)
        def my_func() -> str:
            return "ok"

        my_func()
        my_func()
        my_func()

        assert collector.get_counter("my_counter") == 3

    def test_default_name(self) -> None:
        """Test that default name includes function name."""
        collector = MetricsCollector()
        collector.reset()

        @counted(collector=collector)
        def some_function() -> None:
            pass

        some_function()

        # Default name is {func_name}_calls
        assert collector.get_counter("some_function_calls") == 1
