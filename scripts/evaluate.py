#!/usr/bin/env python3
"""Shrike multi-dimensional evaluation CLI.

Runs all 8 quality dimensions against the test corpus and golden suite.
Produces a composite score + per-dimension breakdown.

Usage:
    python3 scripts/evaluate.py                    # Human-readable report
    python3 scripts/evaluate.py --json             # JSON for CI
    python3 scripts/evaluate.py --check baseline   # CI gate (exits non-zero on regression)
    python3 scripts/evaluate.py --build-golden     # Rebuild golden suite
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shrike.detector.format_detector import detect_format
from shrike.evaluate.dimensions import measure_all
from shrike.evaluate.types import EvaluationReport
from shrike.extractor.pattern_extractor import PatternExtractor
from shrike.validator.ocsf_validator import OCSFValidator


def load_test_data(
    gt_path: str, seed: int = 42,
) -> tuple[list[dict], list[dict]]:
    """Load and split ground truth into train/test."""
    records = [json.loads(line) for line in open(gt_path)]
    real = [r for r in records
            if r.get("source") not in ("synthetic", "contrastive", "fleet_generated")]
    random.seed(seed)
    random.shuffle(real)
    split = int(len(real) * 0.7)
    return real, real[split:]


def load_golden(golden_path: str) -> tuple[list[dict], list[dict]]:
    """Load golden suite and extract canary set (original 12 hand-verified entries)."""
    path = Path(golden_path)
    if not path.exists():
        return [], []
    golden = json.load(open(path))
    # First 12 entries are the hand-verified canary set
    canary = [g for g in golden if "trust_score" not in g]  # Original entries have no trust_score
    return golden, canary


def run_evaluation(
    gt_path: str = "data/ground_truth/classification_ground_truth.jsonl",
    golden_path: str = "tests/fixtures/golden_logs.json",
    seed: int = 42,
) -> EvaluationReport:
    """Run the full 8-dimension evaluation."""
    start = time.monotonic()

    # Load data
    all_gt, test_gt = load_test_data(gt_path, seed)
    golden, canary = load_golden(golden_path)

    # Initialize extractors
    pe = PatternExtractor()
    base_dir = Path(__file__).parent.parent
    schemas_dir = base_dir / "schemas" / "ocsf_v1.3" / "classes"
    validator = OCSFValidator(schemas_dir)

    # Single-pass extraction
    print(f"Extracting {len(test_gt)} test logs...", file=sys.stderr)
    results = []
    for r in test_gt:
        fmt = detect_format(r["raw_log"])
        extraction = pe.try_extract(r["raw_log"], fmt, r["class_uid"], r.get("class_name", ""))
        results.append((extraction, r))

    # Run all 8 dimensions
    print("Scoring 8 dimensions...", file=sys.stderr)
    dimensions = measure_all(
        results=results,
        golden_logs=golden,
        canary_logs=canary,
        ground_truth=all_gt,
        extractor=pe,
        validator=validator,
    )

    elapsed = time.monotonic() - start

    report = EvaluationReport(
        mode="pattern",
        dimensions=dimensions,
        elapsed_seconds=elapsed,
        test_size=len(test_gt),
        golden_size=len(golden),
        canary_size=len(canary),
    )

    return report


def print_report(report: EvaluationReport) -> None:
    """Print human-readable evaluation report."""
    print(f"\nSHRIKE EVALUATION REPORT")
    print(f"{'=' * 70}")
    print(f"  Mode:           {report.mode}")
    print(f"  Test logs:      {report.test_size}")
    print(f"  Golden suite:   {report.golden_size} entries ({report.canary_size} canary)")
    print(f"  Elapsed:        {report.elapsed_seconds:.1f}s")
    print(f"  COMPOSITE:      {report.composite_score:.1f}%")
    print()

    for name, dim in report.dimensions.items():
        bar = "█" * int(dim.score / 2.5)
        print(f"  {name:25s} {dim.score:5.1f}%  {bar}")
        if dim.failures:
            top = dim.failures[0]
            print(f"    └─ Top issue: {top.description}")
    print()

    # Transparency section
    print(f"TRANSPARENCY")
    print(f"{'-' * 70}")
    for name, dim in report.dimensions.items():
        if not dim.failures:
            continue
        print(f"\n  {name.upper()} ({dim.score:.1f}%)")
        print(f"    Measured: {dim.total} items, {dim.passed} passed")
        for f in sorted(dim.failures, key=lambda x: -x.count)[:3]:
            print(f"    - {f.description}")
            if f.category:
                print(f"      Category: {f.category}")
            for ex in f.examples[:1]:
                print(f"      Example: {ex}")


def main():
    parser = argparse.ArgumentParser(description="Shrike Multi-Dimensional Evaluation")
    parser.add_argument("--ground-truth",
                        default="data/ground_truth/classification_ground_truth.jsonl")
    parser.add_argument("--golden", default="tests/fixtures/golden_logs.json")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", action="store_true", help="Output JSON for CI")
    parser.add_argument("--check", type=str, help="Check against baseline JSON file")
    parser.add_argument("--build-golden", action="store_true",
                        help="Rebuild golden suite from ground truth")
    args = parser.parse_args()

    if args.build_golden:
        from shrike.evaluate.golden_builder import build_golden_suite
        added = build_golden_suite(
            ground_truth_path=args.ground_truth,
            existing_golden_path=args.golden,
            output_path=args.golden,
            seed=args.seed,
        )
        print(f"Added {added} golden entries to {args.golden}", file=sys.stderr)
        return

    report = run_evaluation(args.ground_truth, args.golden, args.seed)

    if args.check:
        # CI gate mode
        baseline = json.load(open(args.check))
        baseline_composite = baseline.get("composite_score", 0)
        current_composite = report.composite_score

        # Check canary accuracy (the un-gameable metric)
        canary_dim = report.dimensions.get("canary_accuracy")
        if canary_dim:
            baseline_canary = baseline.get("dimensions", {}).get(
                "canary_accuracy", {}).get("score", 100)
            if canary_dim.score < baseline_canary - 1.0:
                print(f"FAIL: Canary accuracy dropped {baseline_canary:.1f}% → "
                      f"{canary_dim.score:.1f}% (possible self-rationalization)",
                      file=sys.stderr)
                sys.exit(1)

        # Check per-dimension regressions
        for dim_name, dim in report.dimensions.items():
            baseline_score = baseline.get("dimensions", {}).get(
                dim_name, {}).get("score", 0)
            threshold = 2.0  # Allow 2pp tolerance
            if dim.score < baseline_score - threshold:
                print(f"FAIL: {dim_name} dropped {baseline_score:.1f}% → "
                      f"{dim.score:.1f}% (>{threshold}pp regression)",
                      file=sys.stderr)
                sys.exit(1)

        if current_composite > baseline_composite:
            print(f"IMPROVED: composite {baseline_composite:.1f}% → "
                  f"{current_composite:.1f}%", file=sys.stderr)
        else:
            print(f"OK: composite {current_composite:.1f}% "
                  f"(baseline {baseline_composite:.1f}%)", file=sys.stderr)

        # Output updated report
        print(json.dumps(report.to_dict(), indent=2))
        sys.exit(0)

    elif args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
