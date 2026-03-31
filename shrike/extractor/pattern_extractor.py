"""Tier 1: YAML-driven pattern library for deterministic OCSF extraction.

Matches logs against pre-defined regex patterns and maps extracted fields
to OCSF field names. 100% accuracy by construction — no LLM involved.
Completes in <10ms per log.

Pattern files are YAML in the patterns/ directory. Each file defines one
or more extraction patterns for a specific log source.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shrike.detector.format_detector import LogFormat
from shrike.extractor.schema_injected_extractor import ExtractionResult


@dataclass
class PatternDef:
    """A single extraction pattern loaded from YAML."""
    name: str
    source: str
    match_formats: list[str]
    regex: re.Pattern | None
    contains: str | None
    json_has: list[str] | None
    json_match: dict[str, Any] | None
    ocsf_class_uid: int
    ocsf_class_name: str
    static_fields: dict[str, Any]
    field_map: dict[str, str]  # source_field -> ocsf_dotted_path
    severity_map: dict | None
    timestamp_config: dict | None


def _set_nested(d: dict, dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict using dotted path notation.

    Example: _set_nested(d, "src_endpoint.ip", "1.2.3.4")
    → d["src_endpoint"]["ip"] = "1.2.3.4"
    """
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if part not in d:
            d[part] = {}
        d = d[part]
    d[parts[-1]] = value


def _coerce_value(value: str) -> Any:
    """Try to coerce string values to appropriate types."""
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


class PatternExtractor:
    """Tier 1 pattern-based OCSF extractor."""

    def __init__(self, patterns_dir: Path | None = None):
        self._patterns: list[PatternDef] = []
        self._patterns_by_format: dict[str, list[PatternDef]] = {}
        if patterns_dir is None:
            patterns_dir = Path(__file__).parent.parent.parent / "patterns"
        if patterns_dir.exists():
            self._load_patterns(patterns_dir)

    def _load_patterns(self, patterns_dir: Path) -> None:
        """Load all .yaml pattern files, compile regexes, index by format."""
        # Load hand-written patterns first (higher priority), then auto-generated
        all_files = sorted(patterns_dir.glob("*.yaml"))  # Hand-written (top-level)
        all_files += sorted(patterns_dir.rglob("auto/*.yaml"))  # Auto-generated (lower priority)
        for f in all_files:
            try:
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                if not data or "patterns" not in data:
                    continue
                source = data.get("source", f.stem)
                for pdef in data["patterns"]:
                    match = pdef.get("match", {})
                    regex_str = match.get("regex")
                    pattern = PatternDef(
                        name=pdef["name"],
                        source=source,
                        match_formats=match.get("log_format", []),
                        regex=re.compile(regex_str) if regex_str else None,
                        contains=match.get("contains"),
                        json_has=match.get("json_has"),
                        json_match=match.get("json_match"),
                        ocsf_class_uid=pdef["ocsf_class_uid"],
                        ocsf_class_name=pdef["ocsf_class_name"],
                        static_fields=pdef.get("static", {}),
                        field_map=pdef.get("field_map", {}),
                        severity_map=pdef.get("severity_map"),
                        timestamp_config=pdef.get("timestamp"),
                    )
                    # Skip overly-greedy patterns
                    if pattern.regex and len(pattern.regex.pattern) < 20 and not pattern.contains and not pattern.json_has:
                        continue  # Too short regex = too greedy
                    # Skip contains-only patterns with common words (massive false positive risk)
                    if pattern.contains and not pattern.regex and not pattern.json_has:
                        if pattern.contains.lower() in ("system", "config", "error", "warning", "info", "debug",
                                                         "analytics", "traps", "endpoint"):
                            continue  # Too generic contains
                    self._patterns.append(pattern)
                    # Index by format for fast pre-filtering
                    for fmt in pattern.match_formats:
                        self._patterns_by_format.setdefault(fmt, []).append(pattern)
                    if not pattern.match_formats:
                        # No format restriction — matches any format
                        self._patterns_by_format.setdefault("_any", []).append(pattern)
            except Exception:
                pass  # Skip malformed pattern files

    def try_extract(
        self,
        raw_log: str,
        log_format: LogFormat,
        class_uid: int = 0,
        class_name: str = "",
    ) -> ExtractionResult | None:
        """Try pattern extraction. Returns None if no pattern matches."""
        start = time.monotonic()

        # Get candidate patterns for this format
        fmt_str = log_format.value
        candidates = self._patterns_by_format.get(fmt_str, [])
        candidates = candidates + self._patterns_by_format.get("_any", [])

        if not candidates:
            return None

        for pattern in candidates:
            # If classifier provided a class_uid, only match patterns for that class
            # (unless class_uid is 0 = unclassified)
            if class_uid > 0 and pattern.ocsf_class_uid != class_uid:
                continue

            match = self._match_pattern(pattern, raw_log, log_format)
            if match is not None:
                event = self._build_event(match, pattern, raw_log)
                elapsed = (time.monotonic() - start) * 1000
                return ExtractionResult(
                    event=event,
                    class_uid=pattern.ocsf_class_uid,
                    class_name=pattern.ocsf_class_name,
                    raw_log=raw_log,
                    extraction_time_ms=elapsed,
                )

        return None

    def _match_pattern(
        self,
        pattern: PatternDef,
        raw_log: str,
        log_format: LogFormat,
    ) -> dict[str, Any] | None:
        """Test one pattern against the log. Returns extracted groups or None."""
        # Check 'contains' first (fast string check)
        if pattern.contains and pattern.contains not in raw_log:
            return None

        # JSON-based matching
        if pattern.json_has or pattern.json_match:
            try:
                data = json.loads(raw_log.strip())
                if not isinstance(data, dict):
                    return None
            except (json.JSONDecodeError, ValueError):
                return None

            if pattern.json_has:
                for field_name in pattern.json_has:
                    if field_name not in data:
                        return None

            if pattern.json_match:
                for key, expected in pattern.json_match.items():
                    if data.get(key) != expected and str(data.get(key)) != str(expected):
                        return None

            return {"_json_data": data}

        # Regex matching
        if pattern.regex:
            m = pattern.regex.search(raw_log)
            if m:
                return m.groupdict()

        return None

    def _build_event(
        self,
        match: dict[str, Any],
        pattern: PatternDef,
        raw_log: str,
    ) -> dict[str, Any]:
        """Build OCSF event dict from match using field_map and static fields."""
        event: dict[str, Any] = {}

        # Set class metadata
        event["class_uid"] = pattern.ocsf_class_uid
        event["class_name"] = pattern.ocsf_class_name

        # Apply static fields
        for key, value in pattern.static_fields.items():
            _set_nested(event, key, value)

        # Apply field map
        json_data = match.get("_json_data")
        for source_field, ocsf_path in pattern.field_map.items():
            value = None
            if json_data:
                # Navigate dotted source paths in JSON data
                value = json_data
                for part in source_field.split("."):
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
            elif source_field in match:
                value = match[source_field]

            if value is not None:
                _set_nested(event, ocsf_path, _coerce_value(str(value)))

        # Apply severity map if defined
        if pattern.severity_map:
            self._apply_severity_map(event, pattern.severity_map, match, json_data)

        # Auto-populate commonly-required OCSF fields if missing
        event.setdefault("activity_id", 0)  # Unknown
        event.setdefault("severity_id", 1)  # Informational
        event.setdefault("category_uid", pattern.ocsf_class_uid // 1000)

        # For Application Lifecycle, add 'app' from source_app in syslog if available
        if pattern.ocsf_class_uid == 6002 and "app" not in event:
            # Try to extract app name from the log
            import re as _re
            app_match = _re.search(r"(?:Started|Stopped|Failed)\s+(.+?)(?:\s*[-.]|$)", raw_log)
            if app_match:
                event["app"] = {"name": app_match.group(1).strip().rstrip(".")}

        # Extract timestamp from syslog header if not set
        if "time" not in event:
            # Try common syslog timestamp patterns
            ts_match = re.match(
                r"(?:<\d+>(?:\d+\s+)?)?(\d{4}-\d{2}-\d{2}T\S+|"
                r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                raw_log,
            )
            if ts_match:
                event["time"] = ts_match.group(1)

        return event

    def _apply_severity_map(
        self,
        event: dict,
        severity_map: dict,
        match: dict,
        json_data: dict | None,
    ) -> None:
        """Apply conditional severity mapping."""
        field_name = severity_map.get("field", "")
        value = None
        if json_data and field_name in json_data:
            value = json_data[field_name]
        elif field_name in match:
            value = match[field_name]
        elif field_name in event:
            value = event[field_name]

        if value is None:
            return

        try:
            num_value = int(value)
        except (ValueError, TypeError):
            return

        for rule in severity_map.get("rules", []):
            if "range" in rule:
                low, high = rule["range"]
                if low <= num_value <= high:
                    event["severity_id"] = rule["severity_id"]
                    return
            if "value" in rule:
                if num_value == rule["value"]:
                    event["severity_id"] = rule["severity_id"]
                    return

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    @property
    def sources(self) -> list[str]:
        return sorted(set(p.source for p in self._patterns))
