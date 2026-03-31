#!/usr/bin/env python3
"""Benchmark the async ring buffer pipeline.

Loads 100 logs from the ground truth, processes them through the
AsyncShrikePipeline, and reports:
  - Fast path count (rich Tier 1 — no enrichment needed)
  - Enriched count (successfully LLM-enhanced)
  - Dropped count (backpressure)
  - Final rich extraction rate
  - Total wall-clock time

Usage:
    python scripts/benchmark_async.py [--workers 4] [--queue-size 1000] [--logs 100]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shrike.pipeline_async import AsyncShrikePipeline, PipelineResult

# vLLM on dockp02 — subagent tier, thinking disabled via chat_template_kwargs
DEFAULT_API = "http://192.168.20.16:8000/v1"
DEFAULT_MODEL = "subagent"


def load_ground_truth(limit: int = 100) -> list[tuple[str, int, str]]:
    """Load classified logs from the ground truth JSONL files.

    Returns list of (raw_log, class_uid, class_name) tuples.
    """
    data_dir = Path(__file__).parent.parent / "data"
    candidates = [
        data_dir / "ground_truth" / "classification_ground_truth.jsonl",
        data_dir / "classification_ground_truth.jsonl",
        data_dir / "elastic_ground_truth.jsonl",
        data_dir / "sekoia_ground_truth.jsonl",
        data_dir / "lanl_wls_ground_truth.jsonl",
    ]

    logs: list[tuple[str, int, str]] = []
    for path in candidates:
        if not path.exists():
            continue
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                raw_log = rec.get("raw_log", "")
                class_uid = rec.get("class_uid", 0)
                class_name = rec.get("class_name", "")
                if raw_log and class_uid:
                    logs.append((raw_log, class_uid, class_name))
                if len(logs) >= limit:
                    break
        if len(logs) >= limit:
            break

    return logs[:limit]


async def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark async Shrike pipeline")
    parser.add_argument("--api", default=DEFAULT_API, help="LLM API base URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model name")
    parser.add_argument("--workers", type=int, default=4, help="Number of enrichment workers")
    parser.add_argument("--queue-size", type=int, default=1000, help="Enrichment queue size")
    parser.add_argument("--logs", type=int, default=100, help="Number of logs to process")
    parser.add_argument("--wait-enrichment", action="store_true", default=True,
                        help="Wait for all enrichment to complete before reporting")
    args = parser.parse_args()

    # Load ground truth
    print(f"Loading up to {args.logs} logs from ground truth...")
    logs = load_ground_truth(args.logs)
    print(f"  Loaded {len(logs)} logs")

    if not logs:
        print("ERROR: No ground truth logs found. Check data/ directory.")
        sys.exit(1)

    # Track enriched results
    enriched_results: list[PipelineResult] = []
    enrichment_done = asyncio.Event()
    expected_enrichments = 0

    def on_enriched(result: PipelineResult) -> None:
        enriched_results.append(result)
        # Check if all expected enrichments are done
        if len(enriched_results) >= expected_enrichments:
            enrichment_done.set()

    # Create pipeline
    pipe = AsyncShrikePipeline(
        extractor_api=args.api,
        extractor_model=args.model,
        num_workers=args.workers,
        queue_size=args.queue_size,
        on_enriched=on_enriched,
    )

    print(f"\nPipeline config:")
    print(f"  API: {args.api}")
    print(f"  Model: {args.model}")
    print(f"  Workers: {args.workers}")
    print(f"  Queue size: {args.queue_size}")
    print(f"  Pattern count: {pipe._pattern_extractor.pattern_count}")

    # Start workers
    await pipe.start_workers()

    # Process all logs
    print(f"\nProcessing {len(logs)} logs...")
    wall_start = time.monotonic()

    tier1_results = await pipe.process_batch(logs)

    tier1_elapsed = (time.monotonic() - wall_start) * 1000
    stats_after_t1 = pipe.stats

    print(f"\n--- Tier 1 Complete ({tier1_elapsed:.0f}ms) ---")
    print(f"  Processed:   {stats_after_t1['processed']}")
    print(f"  Fast path:   {stats_after_t1['fast_path']} (rich Tier 1, no enrichment needed)")
    print(f"  Queued:      {stats_after_t1['queued']} (sent for LLM enrichment)")
    print(f"  Dropped:     {stats_after_t1['dropped']} (backpressure)")
    print(f"  Avg process: {stats_after_t1['avg_process_ms']:.2f}ms per log")

    expected_enrichments = stats_after_t1["queued"]

    if expected_enrichments > 0 and args.wait_enrichment:
        print(f"\nWaiting for {expected_enrichments} enrichments to complete...")
        # Wait for enrichment workers to drain the queue, with a timeout
        try:
            await asyncio.wait_for(enrichment_done.wait(), timeout=300)
        except asyncio.TimeoutError:
            print("  WARNING: Enrichment timed out after 300s")

        # Also wait for queue to be fully drained
        try:
            await asyncio.wait_for(pipe._queue.join(), timeout=30)
        except asyncio.TimeoutError:
            pass

    wall_total = (time.monotonic() - wall_start) * 1000
    final_stats = pipe.stats

    # Stop workers
    await pipe.stop_workers()

    # Report
    print(f"\n{'=' * 60}")
    print(f"ASYNC PIPELINE BENCHMARK RESULTS")
    print(f"{'=' * 60}")
    print(f"  Logs processed:     {final_stats['processed']}")
    print(f"  Fast path (Tier 1): {final_stats['fast_path']}")
    print(f"  Enriched (LLM):     {final_stats['enriched']}")
    print(f"  Enrichment errors:  {final_stats['enrichment_errors']}")
    print(f"  Dropped (backpres): {final_stats['dropped']}")
    print(f"  Rich extraction rate: {final_stats['rich_rate']:.1%}")
    print(f"")
    print(f"  Tier 1 wall time:   {tier1_elapsed:.0f}ms "
          f"({tier1_elapsed / len(logs):.1f}ms/log)")
    print(f"  Total wall time:    {wall_total:.0f}ms "
          f"({wall_total / len(logs):.1f}ms/log)")
    if final_stats['enriched'] > 0:
        print(f"  Avg enrich latency: {final_stats['avg_enrich_ms']:.0f}ms/log")
    print(f"{'=' * 60}")

    # Show a few sample enriched results
    if enriched_results:
        print(f"\nSample enriched results (first 3):")
        for r in enriched_results[:3]:
            field_count = len([k for k in r.event if k not in {
                "class_uid", "class_name", "category_uid", "category_name",
                "raw_data", "raw_log",
            }])
            print(f"  class={r.class_name}, fields={field_count}, "
                  f"valid={r.valid}, coverage={r.field_coverage:.1%}")


if __name__ == "__main__":
    asyncio.run(main())
