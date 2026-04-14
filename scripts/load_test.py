#!/usr/bin/env python3
"""Load test for Shrike - measures throughput and latency under various conditions."""

import asyncio
import json
import time
import statistics
from pathlib import Path
from typing import Callable

import httpx

# Sample logs for testing
SAMPLE_LOGS = [
    # Syslog BSD
    "Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22",
    # JSON
    '{"timestamp":"2024-03-29T10:00:00Z","level":"INFO","message":"User login","user":"admin","ip":"10.0.0.1"}',
    # CEF
    'CEF:0|Vendor|Product|1.0|100|Event Name|5|src=10.0.0.1 dst=10.0.0.2',
    # AWS GuardDuty
    json.dumps({
        "schemaVersion": "2.0",
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "finding-123",
        "type": "UnauthorizedAccess:EC2/TorRelay",
        "service": {
            "serviceName": "guardduty",
            "action": {
                "actionType": "NetworkConnection",
                "networkConnectionAction": {
                    "remoteIpAddress": "198.51.100.0",
                    "remotePortDetails": {"port": 80},
                    "localIpAddress": "10.0.0.1",
                    "localPortDetails": {"port": 39677}
                }
            }
        },
        "severity": 3,
        "createdAt": "2024-03-29T10:00:00Z"
    }),
]


async def measure_throughput(
    endpoint: str,
    batch_size: int,
    num_batches: int,
    client: httpx.AsyncClient,
) -> dict:
    """Measure throughput for a given batch size and number of batches."""
    logs = SAMPLE_LOGS * (batch_size // len(SAMPLE_LOGS) + 1)
    logs = logs[:batch_size]
    
    latencies = []
    total_bytes = 0
    
    for i in range(num_batches):
        start = time.perf_counter()
        payload = {"logs": logs}
        response = await client.post(endpoint, json=payload)
        elapsed = time.perf_counter() - start
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            continue
            
        latencies.append(elapsed)
        total_bytes += len(json.dumps(payload))
    
    if not latencies:
        return {"error": "No successful requests"}
    
    avg_latency_ms = statistics.mean(latencies) * 1000
    p95_latency_ms = statistics.quantiles(latencies, n=20)[18] * 1000 if len(latencies) >= 20 else max(latencies) * 1000
    events_per_sec = (batch_size * num_batches) / sum(latencies)
    bytes_per_sec = total_bytes / sum(latencies)
    
    return {
        "batch_size": batch_size,
        "num_batches": num_batches,
        "total_events": batch_size * num_batches,
        "avg_latency_ms": round(avg_latency_ms, 2),
        "p95_latency_ms": round(p95_latency_ms, 2),
        "min_latency_ms": round(min(latencies) * 1000, 2),
        "max_latency_ms": round(max(latencies) * 1000, 2),
        "events_per_sec": round(events_per_sec, 2),
        "bytes_per_sec": round(bytes_per_sec, 2),
        "mb_per_sec": round(bytes_per_sec / (1024 * 1024), 2),
    }


async def run_load_tests(base_url: str = "http://localhost:8080") -> None:
    """Run comprehensive load tests."""
    print(f"Starting load tests against {base_url}/v1/ingest")
    print("=" * 70)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Health check
        try:
            resp = await client.get(f"{base_url}/health")
            if resp.status_code != 200:
                print(f"Warning: Health check returned {resp.status_code}")
        except Exception as e:
            print(f"Warning: Could not reach server: {e}")
            print("Make sure Shrike is running: docker compose up -d")
            return
        
        # Test different batch sizes
        test_cases = [
            (1, 100),      # Single events, many batches
            (10, 50),      # Small batches
            (50, 20),      # Medium batches
            (100, 10),     # Large batches
            (500, 5),      # Very large batches
        ]
        
        results = []
        for batch_size, num_batches in test_cases:
            print(f"\nTesting batch_size={batch_size}, num_batches={num_batches}...")
            result = await measure_throughput(
                f"{base_url}/v1/ingest",
                batch_size,
                num_batches,
                client,
            )
            results.append(result)
            
            if "error" not in result:
                print(f"  ✅ {result['events_per_sec']:>10.0f} events/sec | "
                      f"Avg: {result['avg_latency_ms']:>6.1f}ms | "
                      f"P95: {result['p95_latency_ms']:>6.1f}ms")
            else:
                print(f"  ❌ Error: {result['error']}")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    valid_results = [r for r in results if "error" not in r]
    if valid_results:
        best = max(valid_results, key=lambda r: r["events_per_sec"])
        print(f"Best throughput: {best['events_per_sec']:,.0f} events/sec "
              f"(batch size: {best['batch_size']})")
        print(f"Avg latency at best: {best['avg_latency_ms']:.1f}ms")
        print(f"P95 latency at best: {best['p95_latency_ms']:.1f}ms")
    else:
        print("No successful tests completed.")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Shrike load test")
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        help="Shrike server URL (default: http://localhost:8080)"
    )
    
    args = parser.parse_args()
    asyncio.run(run_load_tests(args.url))


if __name__ == "__main__":
    main()
