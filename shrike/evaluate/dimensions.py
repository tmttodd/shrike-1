"""Eight evaluation dimensions for Shrike extraction quality.

Each dimension produces a DimensionScore with a 0-100 score,
pass/fail counts, top failures, and metadata.

All dimensions operate on a shared list of extraction results
(extracted once, scored across all dimensions).

Usage:
    from shrike.evaluate.dimensions import measure_all
    results = [(extraction_result, gt_record), ...]
    report = measure_all(results, golden_logs, canary_logs, validator)
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any

from shrike.detector.format_detector import detect_format
from shrike.evaluate.coercion import OCSFCoercer
from shrike.evaluate.hallucination import HallucinationChecker
from shrike.evaluate.observables import ObservablesBuilder
from shrike.evaluate.types import (
    DimensionScore, FailureDetail,
    get_nested, walk_event,
)
from shrike.extractor.pattern_extractor import PatternExtractor
from shrike.extractor.schema_injected_extractor import ExtractionResult
from shrike.evaluate.attack_coverage import measure_attack_coverage
from shrike.validator.ocsf_validator import OCSFValidator


# --- Dimension 1: Breadth ---

def measure_breadth(
    results: list[tuple[ExtractionResult | None, dict]],
) -> DimensionScore:
    """Field count per extraction. 3+ pattern/alias fields = useful."""
    total = len(results)
    excellent = good = partial = empty = unmatched = 0
    class_failures: dict[int, int] = defaultdict(int)

    for result, gt in results:
        if result is None:
            unmatched += 1
            class_failures[gt.get("class_uid", 0)] += 1
            continue
        conf = result.confidence or {}
        pf = sum(1 for v in conf.values() if v in ("pattern", "alias", "ner"))
        if pf >= 5:
            excellent += 1
        elif pf >= 3:
            good += 1
        elif pf >= 1:
            partial += 1
            class_failures[gt.get("class_uid", 0)] += 1
        else:
            empty += 1
            class_failures[gt.get("class_uid", 0)] += 1

    useful = excellent + good
    score = (useful / total * 100) if total > 0 else 0

    # Top failures by class
    failures = []
    for cls_uid, count in sorted(class_failures.items(), key=lambda x: -x[1])[:10]:
        failures.append(FailureDetail(
            description=f"class {cls_uid}: {count} logs below useful threshold",
            count=count,
            field="",
            category="breadth_gap",
        ))

    return DimensionScore(
        name="breadth",
        score=score,
        total=total,
        passed=useful,
        failures=failures,
        metadata={
            "excellent": excellent, "good": good,
            "partial": partial, "empty": empty, "unmatched": unmatched,
        },
    )


# --- Dimension 2: Accuracy ---

def measure_accuracy(
    extractor: PatternExtractor,
    golden_logs: list[dict],
) -> DimensionScore:
    """Field value correctness against golden expectations."""
    total_fields = 0
    correct_fields = 0
    field_mismatches: dict[str, int] = defaultdict(int)
    field_examples: dict[str, list[str]] = defaultdict(list)
    hallucination_checker = HallucinationChecker()
    hallucination_count = 0

    for golden in golden_logs:
        raw_log = golden["raw_log"]
        class_uid = golden["class_uid"]
        expected = golden.get("expected", {})
        if not expected:
            continue

        fmt = detect_format(raw_log)
        result = extractor.try_extract(raw_log, fmt, class_uid, "")
        if result is None:
            # All expected fields are wrong
            for field_path in expected:
                total_fields += 1
                field_mismatches[field_path] += 1
            continue

        # Check each expected field
        for field_path, expected_value in expected.items():
            total_fields += 1
            actual_value = get_nested(result.event, field_path)

            if _values_match(actual_value, expected_value):
                correct_fields += 1
            else:
                field_mismatches[field_path] += 1
                if len(field_examples[field_path]) < 3:
                    field_examples[field_path].append(
                        f"expected={expected_value!r}, got={actual_value!r}")

        # Hallucination check on extracted event
        h_count = hallucination_checker.count_hallucinations(
            result.event, raw_log, result.confidence)
        hallucination_count += h_count

    score = (correct_fields / total_fields * 100) if total_fields > 0 else 0

    failures = []
    for field_path, count in sorted(field_mismatches.items(), key=lambda x: -x[1])[:10]:
        failures.append(FailureDetail(
            description=f"{field_path} wrong in {count} golden logs",
            count=count,
            field=field_path,
            category="value_mismatch",
            examples=field_examples.get(field_path, []),
        ))

    return DimensionScore(
        name="accuracy",
        score=score,
        total=total_fields,
        passed=correct_fields,
        failures=failures,
        metadata={
            "golden_logs_tested": len(golden_logs),
            "hallucinations_detected": hallucination_count,
        },
    )


# --- Dimension 3: Schema Compliance ---

def measure_schema_compliance(
    results: list[tuple[ExtractionResult | None, dict]],
    validator: OCSFValidator,
) -> DimensionScore:
    """OCSF schema compliance — valid events with no schema errors.

    Measures: what fraction of extracted events pass validation with 0 errors.
    This is binary per event (valid or not), not coverage-based, because
    many OCSF 'required' fields are structurally absent from source logs
    (a firewall log genuinely has no username — penalizing that is wrong).
    """
    total = 0
    valid_count = 0
    missing_fields: dict[str, int] = defaultdict(int)
    error_types: dict[str, int] = defaultdict(int)

    for result, gt in results:
        if result is None:
            continue
        total += 1
        class_uid = gt.get("class_uid", 0)
        validation = validator.validate(result.event, class_uid=class_uid)

        if validation.valid:
            valid_count += 1
        else:
            # Track specific failures
            for error in validation.errors:
                error_types[error.error_type] += 1
                if error.error_type == "missing_required":
                    missing_fields[error.field] += 1

    score = (valid_count / total * 100) if total > 0 else 0

    failures = []
    for field_name, count in sorted(missing_fields.items(), key=lambda x: -x[1])[:10]:
        failures.append(FailureDetail(
            description=f"Required field '{field_name}' missing in {count} events",
            count=count,
            field=field_name,
            category="missing_required",
        ))

    return DimensionScore(
        name="schema_compliance",
        score=score,
        total=total,
        passed=valid_count,
        failures=failures,
    )


# --- Dimension 4: Relationship Integrity ---

ENTITY_PAIRS = [
    ("src_endpoint.ip", "src_endpoint.port", "source endpoint"),
    ("dst_endpoint.ip", "dst_endpoint.port", "destination endpoint"),
    ("actor.user.name", "actor.user.uid", "actor user"),
    ("device.hostname", "device.ip", "device identity"),
    ("process.name", "process.pid", "process identity"),
    ("http_request.http_method", "http_request.url.path", "HTTP request"),
]

# Regex patterns to detect if a partner field's VALUE exists in the raw log
import re as _re
_PARTNER_DETECTORS: dict[str, Any] = {
    "src_endpoint.port": _re.compile(r'(?:port|PORT|:)\s*(\d{1,5})\b'),
    "dst_endpoint.port": _re.compile(r'(?:port|PORT|:)\s*(\d{1,5})\b'),
    "src_endpoint.ip": _re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    "dst_endpoint.ip": _re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    "actor.user.uid": _re.compile(r'(?:uid|UID)[= ]+(\d+)', _re.I),
    "actor.user.name": _re.compile(r'(?:user[= "]+|for\s+|acct=")(\S+)', _re.I),
    "device.ip": _re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    "device.hostname": _re.compile(r'[a-zA-Z][\w.-]{2,}'),
    "process.pid": _re.compile(r'(?:\[(\d{3,})\]|pid[= ]+(\d+))'),
    "process.name": _re.compile(r'(\w+)\[\d+\]'),
    "http_request.url.path": _re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)'),
    "http_request.http_method": _re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'),
}


def measure_relationship_integrity(
    results: list[tuple[ExtractionResult | None, dict]],
) -> DimensionScore:
    """Entity field pairing — only penalizes EXTRACTABLE missing partners.

    When one field of a pair is present but the partner is missing:
    - If the partner value EXISTS in the raw log → extraction miss (penalized)
    - If the partner value is NOT in the raw log → structural sparsity (neutral)
    This separates engine failures from source data limitations.
    """
    paired = 0
    missed = 0      # Partner was in log but not extracted
    sparse = 0      # Partner genuinely not in log
    pair_failures: dict[str, int] = defaultdict(int)

    for result, gt in results:
        if result is None:
            continue
        event = result.event
        raw_log = gt.get("raw_log", "")

        for field_a, field_b, pair_name in ENTITY_PAIRS:
            val_a = get_nested(event, field_a)
            val_b = get_nested(event, field_b)
            has_a = val_a is not None and str(val_a) not in ("", "None", "unknown")
            has_b = val_b is not None and str(val_b) not in ("", "None", "unknown")

            if has_a and has_b:
                paired += 1
            elif has_a and not has_b:
                # Check if field_b's value is extractable from raw log
                detector = _PARTNER_DETECTORS.get(field_b)
                if detector and detector.search(raw_log):
                    missed += 1  # We SHOULD have extracted it
                    pair_failures[pair_name] += 1
                else:
                    sparse += 1  # Genuinely not there
            elif has_b and not has_a:
                detector = _PARTNER_DETECTORS.get(field_a)
                if detector and detector.search(raw_log):
                    missed += 1
                    pair_failures[pair_name] += 1
                else:
                    sparse += 1
            # If neither present, skip

    # Primary score: paired vs missed (extraction quality — what engine controls)
    scoreable = paired + missed
    score = (paired / scoreable * 100) if scoreable > 0 else 100.0

    # Secondary metric: source completeness (operational visibility)
    total_orphaned = missed + sparse
    source_completeness = ((paired / (paired + total_orphaned)) * 100
                           if (paired + total_orphaned) > 0 else 100.0)

    failures = []
    for pair_name, count in sorted(pair_failures.items(), key=lambda x: -x[1]):
        failures.append(FailureDetail(
            description=f"'{pair_name}' pair: partner extractable but missed in {count} events",
            count=count,
            category="extraction_miss",
        ))

    return DimensionScore(
        name="relationship_integrity",
        score=score,
        total=scoreable,
        passed=paired,
        failures=failures,
        metadata={
            "paired": paired,
            "extraction_misses": missed,
            "source_sparse": sparse,
            "source_completeness_pct": round(source_completeness, 1),
            "note": "Primary score measures extraction misses only. "
                    "source_completeness_pct includes structurally sparse pairs "
                    "(operational lever — fix the source, not the engine).",
        },
    )


# --- Dimension 5: Ground Truth Quality ---

def measure_ground_truth_quality(
    ground_truth: list[dict],
    extractor: PatternExtractor,
    sample_size: int = 500,
    seed: int = 42,
) -> DimensionScore:
    """Error rate in ground truth classification labels."""
    # B311: Using random for reproducible sampling in benchmarks (not crypto)
    random.seed(seed)  # nosec B311
    sample = random.sample(ground_truth, min(sample_size, len(ground_truth)))  # nosec B311

    suspected_mislabels = 0
    mislabel_details: list[tuple[int, int, str]] = []  # (gt_class, pattern_class, log_snippet)

    for record in sample:
        raw_log = record.get("raw_log", "")
        gt_class = record.get("class_uid", 0)
        if not raw_log or gt_class == 0:
            continue

        fmt = detect_format(raw_log)
        # Extract WITHOUT constraining to GT class — let patterns find best match
        result = extractor.try_extract(raw_log, fmt, 0, "")
        if result is None:
            continue

        pattern_class = result.class_uid
        conf = result.confidence or {}
        pattern_fields = sum(1 for v in conf.values() if v in ("pattern", "alias", "ner"))

        # If pattern confidently matches a DIFFERENT class (5+ fields)
        if pattern_class != gt_class and pattern_fields >= 5:
            suspected_mislabels += 1
            if len(mislabel_details) < 20:
                mislabel_details.append((gt_class, pattern_class, raw_log[:120]))

    score = ((1 - suspected_mislabels / len(sample)) * 100) if sample else 100

    failures = []
    # Group mislabels by (gt_class, pattern_class)
    mislabel_groups: dict[tuple[int, int], int] = defaultdict(int)
    for gt_cls, pat_cls, _ in mislabel_details:
        mislabel_groups[(gt_cls, pat_cls)] += 1

    for (gt_cls, pat_cls), count in sorted(mislabel_groups.items(), key=lambda x: -x[1]):
        failures.append(FailureDetail(
            description=f"GT says {gt_cls} but patterns match {pat_cls} ({count} logs)",
            count=count,
            category="suspected_mislabel",
        ))

    return DimensionScore(
        name="ground_truth_quality",
        score=score,
        total=len(sample),
        passed=len(sample) - suspected_mislabels,
        failures=failures,
        metadata={"sample_size": len(sample), "suspected_mislabels": suspected_mislabels},
    )


# --- Dimension 6: Cache Quality ---

def measure_cache_quality(
    cache_stats: dict | None = None,
) -> DimensionScore:
    """Fingerprint cache template precision.

    Measures the quality of the fingerprint cache in tiered mode.
    Requires cache_stats from TieredExtractor.cache_stats property.

    Metrics:
    - Hit rate: fraction of lookups that hit the cache
    - Cache utilization: templates learned vs max capacity
    - Promotable ratio: templates ready for pattern promotion

    Args:
        cache_stats: Cache stats dict with keys:
            - size: number of cached templates
            - hits: number of cache hits
            - misses: number of cache misses
            - hit_rate: fraction of lookups that hit (0-1)
            - promotable_count: templates ready for promotion
    """
    if cache_stats is None:
        return DimensionScore(
            name="cache_quality",
            score=100.0,
            total=0,
            passed=0,
            metadata={"skipped": True, "reason": "pattern-only mode"},
        )

    hit_rate = cache_stats.get("hit_rate", 0.0)
    size = cache_stats.get("size", 0)
    hits = cache_stats.get("hits", 0)
    misses = cache_stats.get("misses", 0)
    promotable_count = cache_stats.get("promotable_count", 0)

    total_lookups = hits + misses

    # Score components (each 0-100)
    # 1. Hit rate score: how often cache is used vs falling through
    hit_rate_score = hit_rate * 100

    # 2. Cache utilization: how well the cache is being populated
    # Target: at least 10 templates after warm-up
    utilization_score = min(size / 10 * 100, 100)

    # 3. Promotable ratio: fraction of cache ready for patterns
    # Higher is better — shows cache is learning stable mappings
    promotable_ratio = promotable_count / size if size > 0 else 0.0
    promotable_score = promotable_ratio * 100

    # Composite score: weighted average
    # Hit rate is most important (40%), utilization (30%), promotable (30%)
    score = (
        hit_rate_score * 0.4
        + utilization_score * 0.3
        + promotable_score * 0.3
    )

    return DimensionScore(
        name="cache_quality",
        score=round(score, 1),
        total=total_lookups,
        passed=hits,
        metadata={
            "hit_rate": round(hit_rate, 3),
            "size": size,
            "hits": hits,
            "misses": misses,
            "promotable_count": promotable_count,
            "hit_rate_score": round(hit_rate_score, 1),
            "utilization_score": round(utilization_score, 1),
            "promotable_score": round(promotable_score, 1),
        },
    )


# --- Dimension 7: Type Fidelity ---

def measure_type_fidelity(
    results: list[tuple[ExtractionResult | None, dict]],
) -> DimensionScore:
    """Value type correctness for typed OCSF fields."""
    coercer = OCSFCoercer()
    type_valid = 0
    type_checked = 0
    type_failures: dict[str, int] = defaultdict(int)

    for result, _gt in results:
        if result is None:
            continue
        for field_path, value in walk_event(result.event):
            field_type = coercer.get_type(field_path)
            if field_type is None:
                continue
            type_checked += 1
            if coercer.validate_type(field_path, value):
                type_valid += 1
            else:
                type_failures[f"{field_path} ({field_type})"] += 1

    score = (type_valid / type_checked * 100) if type_checked > 0 else 100

    failures = []
    for type_desc, count in sorted(type_failures.items(), key=lambda x: -x[1])[:10]:
        failures.append(FailureDetail(
            description=f"Type error: {type_desc} invalid in {count} events",
            count=count,
            category="type_error",
        ))

    return DimensionScore(
        name="type_fidelity",
        score=score,
        total=type_checked,
        passed=type_valid,
        failures=failures,
    )


# --- Dimension 8: Observables ---

def measure_observables(
    results: list[tuple[ExtractionResult | None, dict]],
) -> DimensionScore:
    """OCSF observables[] array completeness."""
    builder = ObservablesBuilder()
    total_eligible = 0
    total_built = 0

    for result, _gt in results:
        if result is None:
            continue
        eligible = builder.count_eligible(result.event)
        built = len(builder.build(result.event))
        total_eligible += eligible
        total_built += built

    score = (total_built / total_eligible * 100) if total_eligible > 0 else 0

    return DimensionScore(
        name="observables",
        score=score,
        total=total_eligible,
        passed=total_built,
        metadata={
            "note": "Measures potential observables from extracted fields. "
                    "Score reflects what the builder CAN produce, not what's in the pipeline yet.",
        },
    )


# --- Orchestrator ---

def measure_all(
    results: list[tuple[ExtractionResult | None, dict]],
    golden_logs: list[dict],
    canary_logs: list[dict],
    ground_truth: list[dict],
    extractor: PatternExtractor,
    validator: OCSFValidator,
    tiered: bool = False,
    cache_stats: dict | None = None,
) -> dict[str, DimensionScore]:
    """Run all 8 dimensions and return scores.

    Args:
        results: Shared extraction results [(ExtractionResult, gt_record), ...]
        golden_logs: Golden test entries with expected field values
        canary_logs: Immutable canary set (subset of golden, never auto-modified)
        ground_truth: Full GT dataset for Dimension 5
        extractor: Pattern extractor for accuracy + GT quality dimensions
        validator: OCSF validator for schema compliance
        tiered: Whether tiered mode is active (affects cache quality)
        cache_stats: Cache stats from TieredExtractor.cache_stats (optional)
    """
    dimensions: dict[str, DimensionScore] = {}

    # Dim 1: Breadth
    dimensions["breadth"] = measure_breadth(results)

    # Dim 2: Accuracy (against golden suite)
    dimensions["accuracy"] = measure_accuracy(extractor, golden_logs)

    # Dim 2b: Canary accuracy (immutable reference — the "ground truth for the ground truth")
    if canary_logs:
        dimensions["canary_accuracy"] = measure_accuracy(extractor, canary_logs)

    # Dim 3: Schema Compliance
    dimensions["schema_compliance"] = measure_schema_compliance(results, validator)

    # Dim 4: Relationship Integrity
    dimensions["relationship_integrity"] = measure_relationship_integrity(results)

    # Dim 5: Ground Truth Quality
    dimensions["ground_truth_quality"] = measure_ground_truth_quality(
        ground_truth, extractor)

    # Dim 6: Cache Quality
    dimensions["cache_quality"] = measure_cache_quality(cache_stats=cache_stats)

    # Dim 7: Type Fidelity
    dimensions["type_fidelity"] = measure_type_fidelity(results)

    # Dim 8: Observables
    dimensions["observables"] = measure_observables(results)

    # Dim 9: ATT&CK Detection Coverage (forward direction)
    dimensions["attack_coverage"] = measure_attack_coverage(results)

    return dimensions


# --- Helpers ---

def _values_match(actual: Any, expected: Any) -> bool:
    """Compare values with type coercion tolerance."""
    if actual is None and expected is not None:
        return False
    if actual == expected:
        return True
    # String/int/float coercion
    try:
        if str(actual) == str(expected):
            return True
        if isinstance(expected, (int, float)):
            return float(actual) == float(expected)
        if isinstance(actual, (int, float)):
            return float(actual) == float(expected)
    except (ValueError, TypeError):
        pass
    return False
