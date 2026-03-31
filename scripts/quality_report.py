#!/usr/bin/env python3
"""Shrike Quality Report — the honest numbers.

Measures what matters on UNSEEN data:
  1. Verified extraction rate (3+ pattern-confidence fields)
  2. Per-class and per-format quality
  3. Speed (pattern engine only, no ML)

Usage:
    python scripts/quality_report.py                          # Human-readable
    python scripts/quality_report.py --json                   # JSON for CI
    python scripts/quality_report.py --json > quality_baseline.json  # Save baseline
    python scripts/quality_report.py --check quality_baseline.json   # CI gate
"""

import argparse
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shrike.detector.format_detector import detect_format
from shrike.extractor.pattern_extractor import PatternExtractor


def count_pattern_fields(confidence: dict) -> int:
    """Count fields extracted by patterns (highest confidence)."""
    return sum(1 for v in confidence.values() if v == "pattern")


def count_verified_fields(event: dict, confidence: dict) -> int:
    """Count fields with real values AND pattern/alias confidence."""
    skip = {"class_uid", "class_name", "category_uid", "category_name",
            "activity_id", "severity_id", "raw_data"}
    count = 0
    for k, val in event.items():
        if k in skip:
            continue
        val_str = json.dumps(val) if isinstance(val, (dict, list)) else str(val)
        if "unknown" in val_str.lower():
            continue
        if val_str in ("0", "1", ""):
            continue
        # Only count if confidence is pattern or alias
        if k in confidence and confidence[k] in ("pattern", "alias"):
            count += 1
        elif k not in confidence:
            # Fields set by static (class metadata) — still real if not default
            count += 1
    return count


def classify_quality(event: dict, confidence: dict) -> str:
    """Classify extraction quality — pattern-confidence fields only."""
    pattern_fields = count_pattern_fields(confidence)
    verified = count_verified_fields(event, confidence)

    if pattern_fields >= 5:
        return "excellent"
    elif pattern_fields >= 3:
        return "good"
    elif pattern_fields >= 1:
        return "partial"
    else:
        return "empty"


def run_report(ground_truth_path: str, seed: int = 42) -> dict:
    """Run the quality report and return results as a dict."""
    random.seed(seed)

    records = [json.loads(l) for l in open(ground_truth_path)]
    real = [r for r in records
            if r.get("source") not in ("synthetic", "contrastive", "fleet_generated")]
    random.shuffle(real)

    split = int(len(real) * 0.7)
    test = real[split:]

    pe = PatternExtractor()

    quality_counts = Counter()
    quality_by_class = defaultdict(Counter)
    quality_by_format = defaultdict(Counter)
    times = []

    for r in test:
        fmt = detect_format(r["raw_log"])
        start = time.monotonic()
        result = pe.try_extract(r["raw_log"], fmt, r["class_uid"], r.get("class_name", ""))
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)

        if result is None:
            quality = "unmatched"
        else:
            quality = classify_quality(result.event, result.confidence)

        quality_counts[quality] += 1
        quality_by_class[r["class_uid"]][quality] += 1
        quality_by_format[fmt.value][quality] += 1

    total = len(test)
    useful = quality_counts.get("excellent", 0) + quality_counts.get("good", 0)

    # Per-class useful%
    class_totals = Counter(r["class_uid"] for r in test)
    per_class = {}
    for uid, total_cls in class_totals.most_common(20):
        name = next((r.get("class_name", "") for r in test if r["class_uid"] == uid), "")
        qc = quality_by_class[uid]
        cls_useful = qc.get("excellent", 0) + qc.get("good", 0)
        per_class[str(uid)] = {
            "name": name,
            "total": total_cls,
            "useful": cls_useful,
            "useful_pct": round(cls_useful / total_cls * 100, 1) if total_cls > 0 else 0,
        }

    # Per-format useful%
    per_format = {}
    for fmt_name in ["syslog_bsd", "json", "kv", "cef", "custom", "csv", "clf", "leef", "xml"]:
        qc = quality_by_format.get(fmt_name, Counter())
        total_fmt = sum(qc.values())
        if total_fmt == 0:
            continue
        fmt_useful = qc.get("excellent", 0) + qc.get("good", 0)
        per_format[fmt_name] = {
            "total": total_fmt,
            "useful": fmt_useful,
            "useful_pct": round(fmt_useful / total_fmt * 100, 1) if total_fmt > 0 else 0,
        }

    return {
        "version": "0.1.0",
        "seed": seed,
        "test_size": total,
        "pattern_count": pe.pattern_count,
        "excellent": quality_counts.get("excellent", 0),
        "good": quality_counts.get("good", 0),
        "partial": quality_counts.get("partial", 0),
        "empty": quality_counts.get("empty", 0),
        "unmatched": quality_counts.get("unmatched", 0),
        "useful": useful,
        "useful_pct": round(useful / total * 100, 1),
        "excellent_pct": round(quality_counts.get("excellent", 0) / total * 100, 1),
        "good_pct": round(quality_counts.get("good", 0) / total * 100, 1),
        "speed_p50_ms": round(sorted(times)[len(times) // 2], 3),
        "speed_avg_ms": round(sum(times) / len(times), 3),
        "throughput_per_sec": round(total / (sum(times) / 1000)),
        "per_class": per_class,
        "per_format": per_format,
    }


def print_report(report: dict):
    """Print human-readable report."""
    print(f"SHRIKE QUALITY REPORT")
    print(f"{'=' * 60}")
    print(f"  Test size: {report['test_size']} unseen logs")
    print(f"  Patterns:  {report['pattern_count']}")
    print()

    total = report["test_size"]
    for q in ["excellent", "good", "partial", "empty", "unmatched"]:
        c = report.get(q, 0)
        bar = "█" * int(c / total * 40)
        print(f"    {q:12s}: {c:5d} ({c/total*100:5.1f}%) {bar}")

    print()
    print(f"  USEFUL: {report['useful']}/{total} ({report['useful_pct']}%)")
    print(f"  Speed:  P50={report['speed_p50_ms']}ms | {report['throughput_per_sec']}/sec")
    print()

    print(f"PER-CLASS (top 15):")
    sorted_classes = sorted(report["per_class"].items(),
                           key=lambda x: -x[1]["total"])
    for uid, data in sorted_classes[:15]:
        print(f"  {uid:>5} {data['name'][:25]:25s} "
              f"{data['useful']:>4}/{data['total']:<4} ({data['useful_pct']:>5.1f}%)")

    print()
    print(f"PER-FORMAT:")
    for fmt, data in sorted(report["per_format"].items(), key=lambda x: -x[1]["total"]):
        print(f"  {fmt:15s}: {data['useful']:>4}/{data['total']:<4} ({data['useful_pct']:>5.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Shrike Quality Report")
    parser.add_argument("--ground-truth",
                        default="data/ground_truth/classification_ground_truth.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", action="store_true", help="Output JSON for CI")
    parser.add_argument("--check", type=str, help="Check against baseline JSON file")
    args = parser.parse_args()

    report = run_report(args.ground_truth, args.seed)

    if args.check:
        # CI gate mode — compare against baseline
        baseline = json.load(open(args.check))
        baseline_useful = baseline["useful_pct"]
        current_useful = report["useful_pct"]

        if current_useful < baseline_useful:
            print(f"FAIL: useful dropped {baseline_useful}% → {current_useful}%",
                  file=sys.stderr)
            sys.exit(1)
        elif current_useful > baseline_useful:
            print(f"IMPROVED: useful {baseline_useful}% → {current_useful}%",
                  file=sys.stderr)
            # Output updated baseline
            print(json.dumps(report, indent=2))
            sys.exit(0)
        else:
            print(f"OK: useful unchanged at {current_useful}%", file=sys.stderr)
            sys.exit(0)
    elif args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
