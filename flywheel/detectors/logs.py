"""Log detector — parses Shrike structured logs for ERROR level entries."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

from flywheel.detectors.base import Detection, DetectorResult, IssueSignature, compute_signature_hash

logger = structlog.get_logger("flywheel.detector.logs")

# Threshold: >3 errors in 5 min = issue
ERROR_THRESHOLD = 3
WINDOW_SECONDS = 300

# Component patterns for classification
COMPONENT_PATTERNS = {
    "classifier": re.compile(r"classifier", re.IGNORECASE),
    "ner": re.compile(r"\bNER\b|\bner\b|\bnamed entity\b", re.IGNORECASE),
    "extractor": re.compile(r"extractor|\bextract\b", re.IGNORECASE),
    "validator": re.compile(r"validator|\bvalidate\b", re.IGNORECASE),
    "destination": re.compile(r"destination|\bSplunk\b|\bHEC\b", re.IGNORECASE),
    "pipeline": re.compile(r"pipeline", re.IGNORECASE),
    "wal": re.compile(r"\bWAL\b|\bwal\b", re.IGNORECASE),
}


@dataclass
class LogIssueSignature(IssueSignature):
    """Signature for log-based issues."""

    issue_type: str = ""
    component: str = ""
    error_count: int = 0
    sample_message: str = ""


@dataclass
class LogDetection(Detection):
    """A single ERROR log detection."""

    component: str = ""
    error_count: int = 0
    error_type: str = ""
    sample_messages: list[str] = field(default_factory=list)


class LogDetector:
    """Detect ERROR level logs indicating component failures.

    Parses Shrike's structured logs:
    - ERROR level logs = issue
    - Classify by component (classifier, NER, extractor, validator, destination)
    - Threshold: >3 errors in 5 min = issue
    """

    name = "logs"

    def __init__(
        self,
        log_path: str = "/var/log/shrike",
        error_threshold: int = ERROR_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ) -> None:
        self._log_path = Path(log_path)
        self._error_threshold = error_threshold
        self._window_seconds = window_seconds
        self._last_check_time: float = 0
        self._last_log_position: int = 0

    def detect(self) -> DetectorResult:
        """Run a single detection cycle. Returns issues found."""
        now = time.time()
        if now - self._last_check_time < 30:  # Minimum 30s between checks
            return DetectorResult(detections=[], issues=[])

        self._last_check_time = now
        detections: list[LogDetection] = []
        issues: list[LogDetection] = []

        # Try common log locations
        log_locations = [
            self._log_path,
            Path("/var/log/shrike.log"),
            Path("/data/shrike.log"),
            Path("/data/logs/shrike.log"),
        ]

        for log_path in log_locations:
            if not log_path.is_file():
                continue

            detection = self._scan_log_file(log_path)
            if detection:
                detections.append(detection)
                if detection.error_count > self._error_threshold:
                    issues.append(detection)
            break  # Only scan first found file

        return DetectorResult(detections=detections, issues=issues)

    def _scan_log_file(self, log_path: Path) -> Optional[LogDetection]:
        """Scan a log file for ERROR level entries."""
        try:
            stat = log_path.stat()
            current_size = stat.st_size

            # Handle log rotation
            if current_size < self._last_log_position:
                self._last_log_position = 0

            with open(log_path, "r") as f:
                f.seek(self._last_log_position)
                new_lines = f.readlines()
                self._last_log_position = current_size

            if not new_lines:
                return None

            cutoff = time.time() - self._window_seconds
            errors_by_component: dict[str, list[str]] = {}

            for line in new_lines:
                if not line.strip():
                    continue

                detection = self._parse_log_line(line)
                if not detection:
                    continue

                # Check timestamp
                try:
                    timestamp_str = detection.get("timestamp", "")
                    if timestamp_str:
                        # Handle ISO format timestamps
                        ts = timestamp_str.replace("Z", "")
                        line_time = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
                        if line_time < cutoff:
                            continue
                except (ValueError, OSError):
                    pass

                # Check for ERROR level
                level = detection.get("level", "").upper()
                if level not in ("ERROR", "ERR", "CRITICAL", "FATAL"):
                    continue

                component = self._classify_component(detection.get("message", ""))
                error_msg = detection.get("message", line[:200])

                if component not in errors_by_component:
                    errors_by_component[component] = []
                if len(errors_by_component[component]) < 5:
                    errors_by_component[component].append(error_msg)

            if not errors_by_component:
                return None

            # Aggregate by component
            total_errors = sum(len(msgs) for msgs in errors_by_component.values())
            primary_component = max(errors_by_component, key=lambda c: len(errors_by_component[c]))
            sample_messages = errors_by_component[primary_component]

            return LogDetection(
                component=primary_component,
                error_count=total_errors,
                error_type="error",
                sample_messages=sample_messages,
            )
        except OSError as e:
            logger.warning("Failed to scan log file", path=str(log_path), error=str(e))
            return None

    def _parse_log_line(self, line: str) -> Optional[dict]:
        """Parse a structured log line (JSON or syslog format)."""
        line = line.strip()
        if not line:
            return None

        # Try JSON first
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Try syslog format: "Mar 29 10:00:00 host shrike[123]: message"
        syslog_pattern = re.compile(
            r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+\[\d]+:\s+(.*)$"
        )
        match = syslog_pattern.match(line)
        if match:
            return {"timestamp": match.group(1), "message": match.group(2)}

        # Fall back to plain text
        return {"message": line}

    def _classify_component(self, message: str) -> str:
        """Classify a log message by component based on patterns."""
        for component, pattern in COMPONENT_PATTERNS.items():
            if pattern.search(message):
                return component
        return "unknown"

    def build_signature(self, detection: LogDetection) -> LogIssueSignature:
        """Build an issue signature from a log detection."""
        context = {
            "component": detection.component,
            "error_count": detection.error_count,
            "sample_messages": detection.sample_messages[:3],
        }

        return LogIssueSignature(
            issue_type="log_error",
            component=detection.component,
            error_count=detection.error_count,
            sample_message=detection.sample_messages[0] if detection.sample_messages else "",
            signature_hash=compute_signature_hash(
                "logs", detection.component, context
            ),
        )