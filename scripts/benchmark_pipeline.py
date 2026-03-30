#!/usr/bin/env python3
"""End-to-end Shrike pipeline benchmark.

Tests the full pipeline: detect → classify → filter → extract → validate
on a diverse set of real log lines.
"""

import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from collections import Counter

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shrike.detector.format_detector import detect_format
from shrike.validator.ocsf_validator import OCSFValidator

EXTRACTOR_API = "http://192.168.20.209:11434/v1/chat/completions"
EXTRACTOR_MODEL = "shrike-extractor"

SYSTEM_PROMPT = """You are a log normalization engine. Given a raw log line and an OCSF event class schema, extract the relevant fields into a valid JSON object.

Rules:
1. Output ONLY valid JSON — no explanation, no markdown, no comments.
2. Include class_uid, class_name, category_uid, category_name, activity_id, severity_id, and time.
3. Extract values directly from the log. Do not invent or hallucinate values.
4. Use the exact field names from the schema.
5. If a field's value cannot be determined from the log, omit it entirely.
6. Preserve original values exactly as they appear."""


def load_schemas(schemas_dir: Path) -> dict:
    schemas = {}
    for f in schemas_dir.glob("class_*.json"):
        with open(f) as fh:
            s = json.load(fh)
        schemas[s["class_uid"]] = s
    return schemas


def build_schema_context(schema: dict) -> str:
    attrs = schema.get("attributes", {})
    lines = [f"Class: {schema['class_name']} (UID: {schema['class_uid']})"]
    for name, spec in attrs.items():
        req = "**REQUIRED**" if spec.get("requirement") == "required" else spec.get("requirement", "optional")
        lines.append(f"  - {name} ({spec.get('type','string')}, {req})")
    return "\n".join(lines)


def extract(raw_log: str, schema: dict) -> tuple[dict | None, float]:
    schema_ctx = build_schema_context(schema)
    user = f"Schema:\n{schema_ctx}\n\nRaw log:\n{raw_log}\n\nExtract OCSF JSON:"

    payload = json.dumps({
        "model": EXTRACTOR_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,
        "max_tokens": 2048,
    }).encode()

    req = urllib.request.Request(
        EXTRACTOR_API, data=payload,
        headers={"Content-Type": "application/json"},
    )

    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        content = result["choices"][0]["message"]["content"]
        elapsed = (time.monotonic() - start) * 1000
    except Exception as e:
        return None, 0.0

    # Parse JSON
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"```(?:json)?\s*\n?", "", content).strip().rstrip("`")
    try:
        return json.loads(content), elapsed
    except json.JSONDecodeError:
        # Try finding { ... }
        brace = content.find("{")
        if brace >= 0:
            depth = 0
            for i in range(brace, len(content)):
                if content[i] == "{": depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(content[brace:i+1]), elapsed
                        except:
                            break
        return None, elapsed


def main():
    schemas_dir = Path(__file__).parent.parent / "schemas" / "ocsf_v1.3" / "classes"
    schemas = load_schemas(schemas_dir)
    validator = OCSFValidator(schemas_dir)

    # Load test samples — use ground truth with known class labels
    gt_path = Path(__file__).parent.parent / "data" / "ground_truth" / "classification_ground_truth.jsonl"
    records = [json.loads(l) for l in open(gt_path)]

    # Sample 50 diverse records (1-2 per class)
    import random
    random.seed(42)
    by_class = {}
    for r in records:
        if r.get("source") not in ("synthetic", "contrastive", "fleet_generated"):
            by_class.setdefault(r["class_uid"], []).append(r)

    samples = []
    for uid in sorted(by_class.keys()):
        random.shuffle(by_class[uid])
        samples.extend(by_class[uid][:2])
    random.shuffle(samples)
    samples = samples[:50]

    print(f"Benchmarking {len(samples)} logs across {len(set(s['class_uid'] for s in samples))} classes")
    print(f"Extractor: {EXTRACTOR_MODEL} @ {EXTRACTOR_API}")
    print(f"Schemas: {len(schemas)}")
    print()

    results = []
    for i, sample in enumerate(samples):
        uid = sample["class_uid"]
        name = sample.get("class_name", "")

        # Stage 1: Detect
        t0 = time.monotonic()
        fmt = detect_format(sample["raw_log"])
        detect_ms = (time.monotonic() - t0) * 1000

        # Stage 2: Classify (use ground truth label for now)
        classify_ms = 0  # Using known label

        # Stage 4: Extract
        schema = schemas.get(uid)
        if not schema:
            results.append({"status": "no_schema", "uid": uid})
            continue

        extracted, extract_ms = extract(sample["raw_log"], schema)

        if extracted is None:
            print(f"  {i+1}. {uid} ({name}): EXTRACTION FAILED", file=sys.stderr)
            results.append({"status": "extract_fail", "uid": uid, "extract_ms": extract_ms})
            continue

        # Stage 5: Validate
        t0 = time.monotonic()
        validation = validator.validate(extracted, class_uid=uid)
        validate_ms = (time.monotonic() - t0) * 1000

        field_count = len(extracted)
        total_ms = detect_ms + extract_ms + validate_ms

        results.append({
            "status": "ok",
            "uid": uid,
            "name": name,
            "format": fmt.value,
            "fields": field_count,
            "valid": validation.valid,
            "errors": validation.error_count,
            "warnings": validation.warning_count,
            "coverage": validation.field_coverage,
            "detect_ms": detect_ms,
            "extract_ms": extract_ms,
            "validate_ms": validate_ms,
            "total_ms": total_ms,
        })

        status = "✓" if validation.valid else f"✗ ({validation.error_count} errors)"
        print(f"  {i+1}. {uid} ({name}): {field_count} fields, {status}, {extract_ms:.0f}ms", file=sys.stderr)

    # Summary
    ok = [r for r in results if r["status"] == "ok"]
    valid = [r for r in ok if r["valid"]]
    extract_times = [r["extract_ms"] for r in ok]

    print(f"\n{'='*60}")
    print(f"SHRIKE END-TO-END BENCHMARK")
    print(f"{'='*60}")
    print(f"  Logs tested:       {len(samples)}")
    print(f"  Extraction OK:     {len(ok)}/{len(samples)} ({len(ok)/len(samples)*100:.0f}%)")
    print(f"  Valid OCSF:        {len(valid)}/{len(ok)} ({len(valid)/max(len(ok),1)*100:.0f}%)")
    print(f"  Avg fields:        {sum(r['fields'] for r in ok)/max(len(ok),1):.1f}")
    print(f"  Avg field coverage:{sum(r['coverage'] for r in ok)/max(len(ok),1)*100:.1f}%")
    print(f"\n  Extraction latency:")
    print(f"    Average:  {sum(extract_times)/max(len(extract_times),1):.0f}ms")
    print(f"    P50:      {sorted(extract_times)[len(extract_times)//2]:.0f}ms")
    print(f"    P99:      {sorted(extract_times)[int(len(extract_times)*0.99)]:.0f}ms")

    # Per-class summary
    class_results = Counter()
    class_valid = Counter()
    for r in ok:
        class_results[r["uid"]] += 1
        if r["valid"]:
            class_valid[r["uid"]] += 1

    print(f"\n  Per-class extraction success:")
    for uid in sorted(class_results.keys()):
        total = class_results[uid]
        v = class_valid[uid]
        name = next((r["name"] for r in ok if r["uid"] == uid), "?")
        print(f"    {uid} ({name}): {v}/{total} valid")


if __name__ == "__main__":
    main()
