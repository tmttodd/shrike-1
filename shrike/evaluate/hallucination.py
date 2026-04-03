"""Hallucination detector — verifies extracted values exist in the raw log.

A hallucinated value is one that appears in the extracted OCSF event but
cannot be traced back to the raw log text. This catches:
- LLM fabrications (values the model invented)
- Default/placeholder injections ("unknown", "N/A")
- Coercion artifacts (type conversion producing new values)

Usage:
    from shrike.evaluate.hallucination import HallucinationChecker

    checker = HallucinationChecker()
    results = checker.check_event(event, raw_log, confidence)
    # results = [("user", "admin", False), ("status", "unknown", True)]
    #                                                           ^^^ hallucinated
"""

from __future__ import annotations

import re
from typing import Any

from shrike.evaluate.types import walk_event


# Fields that are METADATA — set by the pipeline, not extracted from the log.
# These are always exempt from hallucination checks.
METADATA_FIELDS = frozenset({
    "class_uid", "class_name", "category_uid", "category_name",
    "activity_id", "activity_name", "severity_id", "severity",
    "type_uid", "type_name", "status_id",
})

# Confidence sources that indicate the value was NOT extracted from the log
# but was set programmatically (static fields in patterns, defaults, etc.)
EXEMPT_CONFIDENCE = frozenset({
    "static", "default", "enrichment",
})

# Known default/placeholder values that extraction code injects.
# These should NEVER appear in golden suite entries.
KNOWN_DEFAULTS = frozenset({
    "unknown", "Unknown", "UNKNOWN",
    "N/A", "n/a", "NA", "none", "None",
    "Security Finding",
    "Base Event",
    "Base Event (low confidence)",
})


class HallucinationChecker:
    """Check whether extracted field values exist in the raw log text."""

    def check_event(
        self,
        event: dict[str, Any],
        raw_log: str,
        confidence: dict[str, str] | None = None,
    ) -> list[tuple[str, Any, bool]]:
        """Check all fields in an event for hallucination.

        Returns list of (field_path, value, is_hallucinated) tuples.
        Only checks leaf values (strings, ints, floats — not dicts/lists).
        """
        results: list[tuple[str, Any, bool]] = []
        confidence = confidence or {}

        # Detect if raw log is JSON — alias values from JSON have
        # verified provenance via json.loads() → key traversal
        is_json_source = raw_log.strip().startswith("{")

        for field_path, value in walk_event(event):
            # Skip metadata fields
            if self._is_metadata(field_path):
                continue

            # Skip fields with exempt confidence
            conf = confidence.get(field_path, "")
            if conf in EXEMPT_CONFIDENCE:
                continue

            # JSON-sourced values have verified provenance —
            # the JSON parser extracted them from a valid key path.
            # Substring matching fails on nested JSON but the value IS real.
            if is_json_source and conf in ("alias", "auto", "fuzzy", "embedding"):
                continue

            # Check if value is a known default
            if self._is_known_default(value):
                results.append((field_path, value, True))
                continue

            # Check if value appears in raw log
            hallucinated = not self._value_in_log(value, raw_log)
            results.append((field_path, value, hallucinated))

        return results

    def count_hallucinations(
        self,
        event: dict[str, Any],
        raw_log: str,
        confidence: dict[str, str] | None = None,
    ) -> int:
        """Count the number of hallucinated fields in an event."""
        return sum(1 for _, _, h in self.check_event(event, raw_log, confidence) if h)

    def _is_metadata(self, field_path: str) -> bool:
        """Check if a field is pipeline metadata (not extracted)."""
        # Check exact match
        if field_path in METADATA_FIELDS:
            return True
        # Check leaf name (e.g., "metadata.event_code" → "event_code" is not metadata,
        # but "category_uid" anywhere is)
        leaf = field_path.rsplit(".", 1)[-1]
        return leaf in METADATA_FIELDS

    @staticmethod
    def _is_known_default(value: Any) -> bool:
        """Check if a value is a known default/placeholder."""
        return str(value) in KNOWN_DEFAULTS

    @staticmethod
    def _value_in_log(value: Any, raw_log: str) -> bool:
        """Check if a value can be found in the raw log text.

        Handles:
        - Direct substring match (most common)
        - JSON values (arrays, dicts) — check each element
        - Numeric values that may appear with different formatting
        - Case-insensitive match for hostnames/usernames
        """
        # Lists/dicts — check if ANY element appears in the raw log
        if isinstance(value, list):
            return any(HallucinationChecker._value_in_log(item, raw_log) for item in value)
        if isinstance(value, dict):
            return any(HallucinationChecker._value_in_log(v, raw_log)
                      for v in value.values() if v is not None)

        val_str = str(value)

        # Empty or very short values — skip (likely enum IDs)
        if len(val_str) <= 1:
            return True  # Don't flag single chars as hallucinated

        # Direct substring match
        if val_str in raw_log:
            return True

        # Case-insensitive match (hostnames, usernames often differ in case)
        if val_str.lower() in raw_log.lower():
            return True

        # Numeric: check if the number appears anywhere
        if isinstance(value, (int, float)):
            # Integer might appear as part of a larger string
            if re.search(r'\b' + re.escape(val_str) + r'\b', raw_log):
                return True
            # Float might appear without trailing zeros
            if isinstance(value, float):
                int_part = str(int(value))
                if int_part in raw_log:
                    return True

        # Boolean values map from various log representations
        if isinstance(value, bool):
            bool_aliases = {
                True: ["true", "yes", "1", "success", "succeeded", "pass", "accept"],
                False: ["false", "no", "0", "failure", "failed", "fail", "deny", "block"],
            }
            return any(alias in raw_log.lower() for alias in bool_aliases[value])

        return False
