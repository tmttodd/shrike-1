#!/usr/bin/env python3
"""Benchmark the trained DistilBERT classifier against ground truth.

Reports per-class precision/recall/F1 and confusion matrix.

Usage:
    python scripts/benchmark_classifier.py \
        --model models/distilbert-ocsf-classifier \
        --ground-truth data/ground_truth/classification_ground_truth.jsonl \
        --output reports/classifier_benchmark.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Benchmark OCSF classifier")
    parser.add_argument("--model", required=True, help="Path to trained classifier")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL")
    parser.add_argument("--output", help="Output JSON report")
    parser.add_argument("--max-records", type=int, default=0, help="Max records (0=all)")
    parser.add_argument("--top-k", type=int, default=3, help="Top-K for accuracy")
    args = parser.parse_args()

    from shrike.classifier.ocsf_classifier import DistilBERTClassifier

    print(f"Loading classifier from {args.model}...", file=sys.stderr)
    classifier = DistilBERTClassifier(Path(args.model))

    # Load ground truth
    records = []
    with open(args.ground_truth) as f:
        for line in f:
            records.append(json.loads(line))
    if args.max_records > 0:
        records = records[:args.max_records]

    print(f"Benchmarking on {len(records)} records...", file=sys.stderr)

    # Run classification
    correct_top1 = 0
    correct_topk = 0
    total = 0
    per_class_correct = Counter()
    per_class_total = Counter()
    confusion = defaultdict(Counter)  # true → predicted → count
    latencies = []

    for i, record in enumerate(records):
        raw_log = record["raw_log"]
        true_uid = record["class_uid"]

        start = time.monotonic()
        result = classifier.classify(raw_log, top_k=args.top_k)
        elapsed_ms = (time.monotonic() - start) * 1000
        latencies.append(elapsed_ms)

        predicted_uid = result.class_uid
        per_class_total[true_uid] += 1
        total += 1

        if predicted_uid == true_uid:
            correct_top1 += 1
            per_class_correct[true_uid] += 1

        # Top-K accuracy
        if result.top_k:
            top_k_uids = [uid for uid, _, _ in result.top_k]
            if true_uid in top_k_uids:
                correct_topk += 1

        confusion[true_uid][predicted_uid] += 1

        if (i + 1) % 500 == 0:
            acc = correct_top1 / total * 100
            print(f"  {i+1}/{len(records)}: top-1 acc={acc:.1f}%", file=sys.stderr)

    # Compute metrics
    top1_acc = correct_top1 / total if total > 0 else 0
    topk_acc = correct_topk / total if total > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    p50_latency = sorted(latencies)[len(latencies) // 2] if latencies else 0
    p99_latency = sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0

    # Per-class metrics
    per_class = {}
    for uid in sorted(per_class_total.keys()):
        total_cls = per_class_total[uid]
        correct_cls = per_class_correct[uid]
        acc = correct_cls / total_cls if total_cls > 0 else 0
        per_class[uid] = {
            "total": total_cls,
            "correct": correct_cls,
            "accuracy": round(acc, 4),
        }

    report = {
        "top1_accuracy": round(top1_acc, 4),
        f"top{args.top_k}_accuracy": round(topk_acc, 4),
        "total_records": total,
        "num_classes": len(per_class_total),
        "latency_ms": {
            "avg": round(avg_latency, 2),
            "p50": round(p50_latency, 2),
            "p99": round(p99_latency, 2),
        },
        "per_class": per_class,
    }

    # Print summary
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Classifier Benchmark Results", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"  Top-1 Accuracy: {top1_acc*100:.1f}%", file=sys.stderr)
    print(f"  Top-{args.top_k} Accuracy: {topk_acc*100:.1f}%", file=sys.stderr)
    print(f"  Total Records:  {total}", file=sys.stderr)
    print(f"  Num Classes:    {len(per_class_total)}", file=sys.stderr)
    print(f"  Avg Latency:    {avg_latency:.1f}ms", file=sys.stderr)
    print(f"  P50 Latency:    {p50_latency:.1f}ms", file=sys.stderr)
    print(f"  P99 Latency:    {p99_latency:.1f}ms", file=sys.stderr)

    # Worst classes
    worst = sorted(per_class.items(), key=lambda x: x[1]["accuracy"])
    print(f"\n  Worst 10 classes:", file=sys.stderr)
    for uid, m in worst[:10]:
        print(f"    {uid}: {m['accuracy']*100:.0f}% ({m['correct']}/{m['total']})", file=sys.stderr)

    # Save report
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {output_path}", file=sys.stderr)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
