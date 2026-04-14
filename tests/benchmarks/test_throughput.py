"""Basic throughput benchmarks for Shrike pipeline.

These are not strict performance tests, but sanity checks to ensure
the pipeline doesn't degrade significantly over time.

Run with: pytest tests/benchmarks/ -v --benchmark
"""

import time
from pathlib import Path

import pytest

from shrike.detector.format_detector import detect_format
from shrike.extractor.pattern_extractor import PatternExtractor


# Sample logs for benchmarking (all have matching patterns)
BENCHMARK_LOGS = [
    "Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22",
    'CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1 dst=10.0.0.2',
    '<14>1 2024-03-29T10:00:00Z host app 1234 - Message here',
    '2024-03-29 10:00:00 INFO user=admin action=login ip=10.0.0.1',
    "Mar 29 10:00:00 host kernel: [12345.678] TCP: request_sock_TCP: Possible SYN flooding",
]


@pytest.fixture
def pattern_extractor() -> PatternExtractor:
    """Create a fresh pattern extractor for each test."""
    return PatternExtractor()


def test_pattern_extraction_throughput(pattern_extractor: PatternExtractor) -> None:
    """Measure pattern extraction throughput. Target: >5000 events/sec."""
    iterations = 1000
    
    start = time.perf_counter()
    for _ in range(iterations):
        for log in BENCHMARK_LOGS:
            fmt = detect_format(log)
            result = pattern_extractor.try_extract(log, fmt, 0, "")
            assert result is not None, f"Failed to extract: {log[:50]}"
    elapsed = time.perf_counter() - start
    
    events_per_sec = (iterations * len(BENCHMARK_LOGS)) / elapsed
    
    # Assert minimum throughput (adjust based on actual performance)
    assert events_per_sec > 5000, f"Throughput too low: {events_per_sec:.0f} events/sec"
    
    print(f"\n  Throughput: {events_per_sec:,.0f} events/sec")
    print(f"  Avg latency: {(elapsed / (iterations * len(BENCHMARK_LOGS))) * 1000:.2f}ms/event")


def test_format_detection_throughput() -> None:
    """Measure format detection throughput. Target: >20000 events/sec."""
    iterations = 5000
    
    start = time.perf_counter()
    for _ in range(iterations):
        for log in BENCHMARK_LOGS:
            fmt = detect_format(log)
            assert fmt is not None
    elapsed = time.perf_counter() - start
    
    events_per_sec = (iterations * len(BENCHMARK_LOGS)) / elapsed
    
    assert events_per_sec > 20000, f"Throughput too low: {events_per_sec:.0f} events/sec"
    
    print(f"\n  Throughput: {events_per_sec:,.0f} events/sec")
    print(f"  Avg latency: {(elapsed / (iterations * len(BENCHMARK_LOGS))) * 1000:.3f}ms/event")


@pytest.mark.skip(reason="Integration test requires running server")
async def test_http_endpoint_throughput() -> None:
    """Measure HTTP endpoint throughput. Requires running Shrike server."""
    # This would use httpx.AsyncClient to POST batches to /v1/ingest
    # and measure throughput. Skip for now as it requires infrastructure.
    pass
