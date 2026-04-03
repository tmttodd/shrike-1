"""CLI entry point for Shrike pipeline.

Usage:
    python -m shrike --input sample.log
    echo "log line" | python -m shrike
    python -m shrike --input sample.log --filter noise-reduction --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Shrike — any log format in, OCSF JSON out",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input log file (one log per line). Use - for stdin.",
        default="-",
    )
    parser.add_argument(
        "--classifier-model",
        type=str,
        help="Path to the classifier model directory",
    )
    parser.add_argument(
        "--classifier-type",
        choices=["distilbert", "embedding"],
        default="distilbert",
        help="Classifier backend (default: distilbert)",
    )
    parser.add_argument(
        "--extractor-api",
        type=str,
        default="http://localhost:11434/v1",
        help="Extractor LLM API base URL (default: Ollama local)",
    )
    parser.add_argument(
        "--extractor-model",
        type=str,
        default="shrike-extractor",
        help="Extractor model name",
    )
    parser.add_argument(
        "--filter",
        type=str,
        help="Active filter pack name (e.g., noise-reduction)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "summary"],
        default="jsonl",
        help="Output format (default: jsonl)",
    )
    parser.add_argument(
        "--schemas",
        type=str,
        help="Path to OCSF schema directory",
    )
    parser.add_argument(
        "--filters-dir",
        type=str,
        help="Path to filter packs directory",
    )
    parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Only run format detection (Stage 1)",
    )
    parser.add_argument(
        "--classify-only",
        action="store_true",
        help="Only run detection + classification (Stages 1-2)",
    )
    parser.add_argument(
        "--no-auto-fix",
        action="store_true",
        help="Disable automatic validation fixes",
    )

    args = parser.parse_args()

    # Read input
    if args.input == "-":
        lines = [line.rstrip("\n") for line in sys.stdin if line.strip()]
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        with open(input_path) as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]

    if not lines:
        print("No input lines to process.", file=sys.stderr)
        sys.exit(0)

    # Detect-only mode
    if args.detect_only:
        from shrike.detector.format_detector import detect_format
        for line in lines:
            fmt = detect_format(line)
            if args.format == "json":
                print(json.dumps({"raw_log": line[:100], "format": fmt.value}))
            else:
                print(f"{fmt.value}\t{line[:120]}")
        return

    # Full or classify-only pipeline
    from shrike.pipeline import ShrikePipeline

    pipe = ShrikePipeline(
        classifier_model=args.classifier_model,
        classifier_type=args.classifier_type,
        extractor_api=args.extractor_api,
        extractor_model=args.extractor_model,
        schemas_dir=args.schemas,
        filter_packs_dir=args.filters_dir,
        active_filter=args.filter,
        auto_fix=not args.no_auto_fix,
    )

    results = []
    kept = 0
    dropped = 0

    for i, line in enumerate(lines):
        result = pipe.process(line)
        results.append(result)

        if result.dropped:
            dropped += 1
        else:
            kept += 1

        if args.format == "jsonl" and not result.dropped:
            if args.classify_only:
                print(json.dumps({
                    "raw_log": line[:200],
                    "format": result.log_format.value,
                    "class_uid": result.class_uid,
                    "class_name": result.class_name,
                    "confidence": round(result.classification_confidence, 4),
                }))
            else:
                print(json.dumps(result.to_dict()))

    if args.format == "summary":
        total = len(results)
        valid = sum(1 for r in results if r.valid)
        avg_total = sum(r.total_ms for r in results) / max(total, 1)
        avg_extract = sum(r.extract_ms for r in results if not r.dropped) / max(kept, 1)

        print(f"\n{'='*60}")
        print(f"Shrike Pipeline Summary")
        print(f"{'='*60}")
        print(f"  Total logs:      {total}")
        print(f"  Kept:            {kept}")
        print(f"  Dropped:         {dropped}")
        print(f"  Valid OCSF:      {valid}/{kept} ({valid/max(kept,1)*100:.1f}%)")
        print(f"  Avg total time:  {avg_total:.1f}ms")
        print(f"  Avg extract:     {avg_extract:.1f}ms")

        # Class distribution
        class_counts: dict[str, int] = {}
        for r in results:
            if not r.dropped:
                key = f"{r.class_uid} ({r.class_name})"
                class_counts[key] = class_counts.get(key, 0) + 1

        print(f"\n  Class Distribution:")
        for cls, count in sorted(class_counts.items(), key=lambda x: -x[1])[:15]:
            print(f"    {cls}: {count}")

    elif args.format == "json":
        # Full JSON array output
        output = [r.to_dict() for r in results if not r.dropped]
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
