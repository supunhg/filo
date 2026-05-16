"""
Performance profiling for identifying bottlenecks in file analysis.
"""

import cProfile
import logging
import pstats
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import StringIO
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


@dataclass
class TimingResult:
    """Result from timing a function."""

    name: str
    duration: float
    calls: int = 1
    avg_duration: float = 0.0

    def __post_init__(self):
        self.avg_duration = self.duration / self.calls if self.calls > 0 else 0


@dataclass
class ProfileReport:
    """Performance profile report."""

    total_duration: float
    timings: Dict[str, TimingResult] = field(default_factory=dict)
    profile_data: Optional[str] = None

    def add_timing(self, name: str, duration: float) -> None:
        """Add a timing measurement."""
        if name in self.timings:
            existing = self.timings[name]
            existing.duration += duration
            existing.calls += 1
            existing.avg_duration = existing.duration / existing.calls
        else:
            self.timings[name] = TimingResult(name=name, duration=duration)

    def get_sorted_timings(self) -> List[TimingResult]:
        """Get timings sorted by duration (descending)."""
        return sorted(self.timings.values(), key=lambda x: x.duration, reverse=True)

    def format_report(self) -> str:
        """Format report as string."""
        lines = [
            "=" * 70,
            "PERFORMANCE PROFILE REPORT",
            "=" * 70,
            f"Total Duration: {self.total_duration:.4f}s",
            "",
            "Top Operations by Time:",
            "-" * 70,
            f"{'Operation':<30} {'Time (s)':<12} {'Calls':<8} {'Avg (s)':<12}",
            "-" * 70,
        ]

        for timing in self.get_sorted_timings()[:20]:  # Top 20
            lines.append(
                f"{timing.name:<30} {timing.duration:<12.4f} {timing.calls:<8} {timing.avg_duration:<12.6f}"
            )

        lines.append("=" * 70)

        return "\n".join(lines)


class Profiler:
    """
    Performance profiler for analyzing bottlenecks.

    Features:
    - Function timing
    - Context manager for easy timing
    - cProfile integration
    - Detailed reports
    """

    def __init__(self, enabled: bool = True) -> None:
        """
        Initialize profiler.

        Args:
            enabled: Enable profiling (can disable for production)
        """
        self.enabled = enabled
        self.report = ProfileReport(total_duration=0.0)
        self._start_time: Optional[float] = None
        self._profiler: Optional[cProfile.Profile] = None

    def start(self) -> None:
        """Start profiling session."""
        if not self.enabled:
            return

        self._start_time = time.time()
        self._profiler = cProfile.Profile()
        self._profiler.enable()
        logger.info("Profiling started")

    def stop(self) -> ProfileReport:
        """
        Stop profiling and generate report.

        Returns:
            ProfileReport with results
        """
        if not self.enabled or not self._start_time:
            return self.report

        if self._profiler:
            self._profiler.disable()

            # Capture cProfile output
            s = StringIO()
            ps = pstats.Stats(self._profiler, stream=s)
            ps.sort_stats("cumulative")
            ps.print_stats(30)  # Top 30 functions

            self.report.profile_data = s.getvalue()

        self.report.total_duration = time.time() - self._start_time
        logger.info(f"Profiling stopped. Duration: {self.report.total_duration:.4f}s")

        return self.report

    @contextmanager
    def time_operation(self, name: str):
        """
        Context manager for timing an operation.

        Args:
            name: Operation name

        Example:
            with profiler.time_operation("analyze_file"):
                result = analyzer.analyze(data)
        """
        if not self.enabled:
            yield
            return

        start = time.time()
        try:
            yield
        finally:
            duration = time.time() - start
            self.report.add_timing(name, duration)

    def time_function(self, name: Optional[str] = None):
        """
        Decorator for timing a function.

        Args:
            name: Optional custom name (defaults to function name)

        Example:
            @profiler.time_function()
            def analyze_file(data):
                ...
        """

        def decorator(func: Callable) -> Callable:
            timing_name = name or func.__name__

            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)

                with self.time_operation(timing_name):
                    return func(*args, **kwargs)

            return wrapper

        return decorator


# Global profiler instance
_global_profiler: Optional[Profiler] = None


def get_profiler(enabled: bool = True) -> Profiler:
    """Get or create global profiler instance."""
    global _global_profiler

    if _global_profiler is None:
        _global_profiler = Profiler(enabled=enabled)

    return _global_profiler


def profile_analysis(func: Callable) -> Callable:
    """
    Decorator to profile an analysis function.

    Example:
        @profile_analysis
        def my_analysis(data):
            ...
    """
    profiler = get_profiler()
    return profiler.time_function()(func)


@contextmanager
def profile_session():
    """
    Context manager for a profiling session.

    Example:
        with profile_session() as profiler:
            # ... do work ...
            pass

        print(profiler.report.format_report())
    """
    profiler = get_profiler()
    profiler.start()

    try:
        yield profiler
    finally:
        profiler.stop()
