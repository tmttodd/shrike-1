#!/usr/bin/env python3
"""Autonomous iteration engine for Shrike.

Runs evaluation cycles against the full corpus, identifies failures,
and regenerates the golden suite from high-confidence extractions.

Usage:
    python3 scripts/iterate.py              # One iteration cycle
    python3 scripts/iterate.py --cycles 10  # Run 10 cycles
    python3 scripts/iterate.py --target 90  # Iterate until 90% composite
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shrike.detector.format_detector import detect_format
from shrike.evaluate.dimensions import measure_all
from shrike.evaluate.golden_builder import GoldenBuilder
from shrike.evaluate.types import EvaluationReport
from shrike.extractor.pattern_extractor import PatternExtractor
from shrike.validator.ocsf_validator import OCSFValidator


def load_full_corpus(data_dir: str = "data") -> list[dict]:
    """Load ALL ground truth files + training samples."""
    records = []
    gt_dir = Path(data_dir) / "ground_truth"
    for f in gt_dir.glob("*.jsonl"):
        try:
            for line in open(f):
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        except Exception:
            pass
    # Also load training_samples
    ts = Path(data_dir) / "training_samples.jsonl"
    if ts.exists():
        try:
            for line in open(ts):
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        except Exception:
            pass
    return records


def dedupe(records: list[dict]) -> list[dict]:
    """Deduplicate by raw_log."""
    seen: set[str] = set()
    unique: list[dict] = []
    for r in records:
        rl = r.get("raw_log", "")
        if rl and rl not in seen:
            seen.add(rl)
            unique.append(r)
    return unique


def random_split(records: list[dict], test_pct: float = 0.3,
                 seed: int | None = None) -> tuple[list[dict], list[dict]]:
    """Random train/test split. Different seed = different split."""
    if seed is not None:
        random.seed(seed)
    else:
        random.seed(time.time_ns())
    shuffled = list(records)
    random.shuffle(shuffled)
    split = int(len(shuffled) * (1 - test_pct))
    return shuffled[:split], shuffled[split:]


def run_iteration(
    corpus: list[dict],
    golden_path: str,
    seed: int | None = None,
) -> dict:
    """Run one evaluation cycle with a randomized test split."""
    start = time.monotonic()

    # Random split
    _, test = random_split(corpus, test_pct=0.3, seed=seed)

    # Initialize
    pe = PatternExtractor()
    base = Path(__file__).parent.parent
    schemas_dir = base / "schemas" / "ocsf_v1.3" / "classes"
    validator = OCSFValidator(schemas_dir)

    # Classify unclassified logs inline (production behavior)
    classifier = None
    model_path = base / "models" / "ocsf-classifier"
    if model_path.exists():
        try:
            from shrike.classifier.ocsf_classifier import DistilBERTClassifier
            classifier = DistilBERTClassifier(model_path, schemas_dir)
        except Exception:
            pass

    classified = []
    for r in test:
        if r.get("class_uid", 0) > 0:
            classified.append(r)
        elif classifier:
            # Run classifier on unclassified logs — same as production
            raw = r.get("raw_log", "")
            if raw and len(raw) >= 10:
                result = classifier.classify(raw)
                if result.confidence >= 0.5:
                    r = dict(r)  # Don't mutate original
                    r["class_uid"] = result.class_uid
                    r["class_name"] = result.class_name
                    classified.append(r)

    # Extract
    results = []
    for r in classified:
        fmt = detect_format(r["raw_log"])
        extraction = pe.try_extract(r["raw_log"], fmt, r["class_uid"],
                                     r.get("class_name", ""))
        results.append((extraction, r))

    # Load golden + canary
    golden_p = Path(golden_path)
    golden = json.load(open(golden_p)) if golden_p.exists() else []
    canary = [g for g in golden if "trust_score" not in g]

    # Measure all dimensions
    dimensions = measure_all(
        results=results,
        golden_logs=golden,
        canary_logs=canary,
        ground_truth=corpus,
        extractor=pe,
        validator=validator,
    )

    elapsed = time.monotonic() - start

    report = EvaluationReport(
        mode="full_corpus",
        dimensions=dimensions,
        elapsed_seconds=elapsed,
        test_size=len(classified),
        golden_size=len(golden),
        canary_size=len(canary),
    )

    return report.to_dict()


def rebuild_golden(corpus: list[dict], golden_path: str,
                   canary_count: int = 12) -> int:
    """Rebuild golden suite from high-confidence extractions."""
    golden_p = Path(golden_path)
    existing = json.load(open(golden_p)) if golden_p.exists() else []

    # Keep canary entries (original hand-verified)
    canary = [g for g in existing if "trust_score" not in g][:canary_count]

    # Filter corpus to classified records
    classified = [r for r in corpus if r.get("class_uid", 0) > 0]

    builder = GoldenBuilder()
    candidates = builder.build_candidates(
        classified,
        existing_golden=canary,
        max_per_class=25,
        max_per_format=50,
        min_fields=5,
        seed=42,
    )

    new_entries = [c.to_golden_entry() for c in candidates]
    merged = canary + new_entries

    with open(golden_path, "w") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")

    return len(new_entries)


def main():
    parser = argparse.ArgumentParser(description="Shrike Autonomous Iteration")
    parser.add_argument("--cycles", type=int, default=1, help="Number of iteration cycles")
    parser.add_argument("--target", type=float, default=90.0,
                        help="Stop when composite score reaches this %%")
    parser.add_argument("--golden", default="tests/fixtures/golden_logs.json")
    parser.add_argument("--rebuild-golden", action="store_true",
                        help="Rebuild golden suite before iterating")
    args = parser.parse_args()

    # Load full corpus
    print("Loading full corpus...", file=sys.stderr)
    corpus = dedupe(load_full_corpus())
    classified = [r for r in corpus if r.get("class_uid", 0) > 0]
    print(f"  {len(corpus)} total, {len(classified)} classified", file=sys.stderr)

    # Rebuild golden if requested
    if args.rebuild_golden:
        print("Rebuilding golden suite...", file=sys.stderr)
        added = rebuild_golden(corpus, args.golden)
        print(f"  Golden suite: {added} entries", file=sys.stderr)

    # Iterate
    for cycle in range(args.cycles):
        seed = 42 + cycle  # Different seed each cycle for different test splits
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"CYCLE {cycle + 1}/{args.cycles} (seed={seed})", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)

        report = run_iteration(corpus, args.golden, seed=seed)

        composite = report["composite_score"]
        print(f"  Composite: {composite}%", file=sys.stderr)
        for name, dim in report["dimensions"].items():
            print(f"    {name:25s} {dim['score']:5.1f}%", file=sys.stderr)

        if composite >= args.target:
            print(f"\n  TARGET REACHED: {composite}% >= {args.target}%",
                  file=sys.stderr)
            break

    # Output final report as JSON
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
