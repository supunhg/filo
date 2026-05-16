"""Tests for performance profiling."""

import time

from filo.profiler import Profiler, profile_session, profile_analysis


def test_profiler_initialization():
    """Test profiler initialization."""
    profiler = Profiler(enabled=True)
    
    assert profiler.enabled is True
    assert profiler.report.total_duration == 0.0


def test_profiler_disabled():
    """Test disabled profiler."""
    profiler = Profiler(enabled=False)
    
    profiler.start()
    time.sleep(0.1)
    report = profiler.stop()
    
    # Should not track anything when disabled
    assert report.total_duration == 0.0


def test_profiler_basic_timing():
    """Test basic timing functionality."""
    profiler = Profiler(enabled=True)
    profiler.start()
    
    time.sleep(0.1)
    
    report = profiler.stop()
    
    assert report.total_duration >= 0.1


def test_time_operation_context_manager():
    """Test time_operation context manager."""
    profiler = Profiler(enabled=True)
    
    with profiler.time_operation("test_op"):
        time.sleep(0.05)
    
    report = profiler.report
    
    assert "test_op" in report.timings
    assert report.timings["test_op"].duration >= 0.05


def test_multiple_operations():
    """Test timing multiple operations."""
    profiler = Profiler(enabled=True)
    
    with profiler.time_operation("op1"):
        time.sleep(0.05)
    
    with profiler.time_operation("op2"):
        time.sleep(0.03)
    
    report = profiler.report
    
    assert len(report.timings) == 2
    assert "op1" in report.timings
    assert "op2" in report.timings


def test_repeated_operation():
    """Test timing same operation multiple times."""
    profiler = Profiler(enabled=True)
    
    for _ in range(3):
        with profiler.time_operation("repeated"):
            time.sleep(0.01)
    
    report = profiler.report
    timing = report.timings["repeated"]
    
    assert timing.calls == 3
    assert timing.duration >= 0.03
    assert timing.avg_duration >= 0.01


def test_time_function_decorator():
    """Test function timing decorator."""
    profiler = Profiler(enabled=True)
    
    @profiler.time_function("test_func")
    def slow_function():
        time.sleep(0.05)
        return 42
    
    result = slow_function()
    
    assert result == 42
    assert "test_func" in profiler.report.timings
    assert profiler.report.timings["test_func"].duration >= 0.05


def test_profile_session_context_manager():
    """Test profile_session context manager."""
    with profile_session() as profiler:
        with profiler.time_operation("work"):
            time.sleep(0.05)
    
    report = profiler.report
    
    assert report.total_duration >= 0.05
    assert "work" in report.timings


def test_sorted_timings():
    """Test getting sorted timings."""
    profiler = Profiler(enabled=True)
    
    with profiler.time_operation("slow"):
        time.sleep(0.1)
    
    with profiler.time_operation("fast"):
        time.sleep(0.01)
    
    sorted_timings = profiler.report.get_sorted_timings()
    
    # Should be sorted by duration (descending)
    assert sorted_timings[0].name == "slow"
    assert sorted_timings[1].name == "fast"


def test_format_report():
    """Test report formatting."""
    profiler = Profiler(enabled=True)
    profiler.start()
    
    with profiler.time_operation("test"):
        time.sleep(0.05)
    
    profiler.stop()
    
    formatted = profiler.report.format_report()
    
    assert "PERFORMANCE PROFILE REPORT" in formatted
    assert "test" in formatted
    assert "Total Duration" in formatted


def test_profile_analysis_decorator():
    """Test profile_analysis decorator."""
    @profile_analysis
    def analyze_data(data):
        time.sleep(0.01)
        return len(data)
    
    result = analyze_data(b"test data")
    
    assert result == 9
