"""WAL detector — monitors /data/wal for failed events."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

from flywheel.detectors.base import Detection, DetectorResult, IssueSignature, compute_signature_hash

logger = structlog.get_logger("flywheel.detector.wal")

# Threshold: >5 failures in 10 min = issue
FAILURE_THRESHOLD = 5
WINDOW_SECONDS = 600


@dataclass
class WalIssueSignature(IssueSignature):
    """Signature for WAL-related issues."""

    issue_type: str = ""  # "extraction_failure", "routing_failure", "validation_failure"
    error_type: str = ""
    component: str = ""
    failure_count: int = 0


@dataclass
class WalDetection(Detection):
    """A single WAL failure detection."""

    dest_name: str = ""
    failure_count: int = 0
    error_type: str = ""
    component: str = ""
    sample_errors: list[str] = field(default_factory=list)


class WalDetector:
    """Detect WAL failures indicating extraction or routing problems.

    Monitors /data/wal for failed events:
    - New WAL files appearing = extraction/routing failure
    - Parse WAL, extract error type, classify by component
    - Threshold: >5 failures in 10 min = issue
    """

    name = "wal"

    def __init__(
        self,
        wal_dir: str = "/data/wal",
        failure_threshold: int = FAILURE_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ) -> None:
        self._wal_dir = Path(wal_dir)
        self._failure_threshold = failure_threshold
        self._window_seconds = window_seconds
        self._last_check_time: float = 0
        self._last_known_files: dict[str, float] = {}

    def detect(self) -> DetectorResult:
        """Run a single detection cycle. Returns issues found."""
        now = time.time()
        if now - self._last_check_time < 30:  # Minimum 30s between checks
            return DetectorResult(detections=[], issues=[])

        self._last_check_time = now
        detections: list[WalDetection] = []
        issues: list[WalDetection] = []

        if not self._wal_dir.is_dir():
            logger.warning("WAL directory not accessible", wal_dir=str(self._wal_dir))
            return DetectorResult(detections=[], issues=[])

        # Check for new or modified WAL files
        for wal_path in self._wal_dir.glob("*.wal.jsonl"):
            detection = self._scan_wal_file(wal_path)
            if detection:
                detections.append(detection)
                if detection.failure_count > self._failure_threshold:
                    issues.append(detection)

        return DetectorResult(detections=detections, issues=issues)

    def _scan_wal_file(self, wal_path: Path) -> Optional[WalDetection]:
        """Scan a WAL file for failed events."""
        try:
            stat = wal_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size

            # Skip if file hasn't changed since last check
            last_size = self._last_known_files.get(wal_path.name, 0)
            if size <= last_size and mtime < time.time() - self._window_seconds:
                return None

            self._last_known_files[wal_path.name] = size

            # Parse recent entries (last N lines to bound memory)
            failures: list[dict] = []
            sample_errors: list[str] = []

            with open(wal_path, "r") as f:
                # Read last 1000 lines max
                lines = f.readlines[-1000:] if stat.st_size > 100_000 else f.readlines()

            cutoff = time.time() - self._window_seconds
            for line in lines:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    # Check for failure markers
                    if self._is_failure_event(event):
                        failures.append(event)
                        if len(sample_errors) < 5:
                            sample_errors.append(self._extract_error_message(event))
                except json.JSONDecodeError:
                    continue

            if not failures:
                return None

            # Classify failures by component and error type
            error_type, component = self._classify_failures(failures)

            return WalDetection(
                dest_name=wal_path.stem.replace(".wal", ""),
                failure_count=len(failures),
                error_type=error_type,
                component=component,
                sample_errors=sample_errors,
            )
        except OSError as e:
            logger.warning("Failed to scan WAL file", path=str(wal_path), error=str(e))
            return None

    def _is_failure_event(self, event: dict) -> bool:
        """Check if a WAL event represents a failure."""
        # Check for explicit failure marker
        if event.get("_shrike_failure") or event.get("failed"):
            return True

        # Check for error status
        status = event.get("status", "")
        if status in ("failed", "error", "rejected"):
            return True

        # Check for retry count indicating repeated failures
        retry_count = event.get("retry_count", 0)
        if retry_count >= 3:
            return True

        return False

    def _extract_error_message(self, event: dict) -> str:
        """Extract a short error message from a failed event."""
        # Try structured error fields first
        if event.get("error"):
            return str(event["error"])[:200]
        if event.get("error_message"):
            return str(event["error_message"])[:200]
        if event.get("message"):
            return str(event["message"])[:200]

        # Fall back to raw event preview
        raw = event.get("raw_event", "")
        if raw:
            return raw[:200]

        return json.dumps(event)[:200]

    def _classify_failures(self, failures: list[dict]) -> tuple[str, str]:
        """Classify failures by component and error type."""
        from collections import Counter

        components: list[str] = []
        error_types: list[str] = []

        for event in failures:
            # Determine component from OCSF class or source
            ocsf_class = event.get("class_name", "") or event.get("category_uid", "")
            if ocsf_class:
                components.append(str(ocsf_class))

            # Determine error type
            error_type = event.get("error_type", "") or event.get("status", "unknown")
            error_types.append(str(error_type))

        # Return most common
        component_counter = Counter(components)
        error_type_counter = Counter(error_types)

        most_common_component = component_counter.most_common(1)[0][0] if component_counter else "unknown"
        most_common_error = error_type_counter.most_common(1)[0][0] if error_type_counter else "unknown"

        return most_common_error, most_common_component

    def build_signature(self, detection: WalDetection) -> WalIssueSignature:
        """Build an issue signature from a WAL detection."""
        context = {
            "dest_name": detection.dest_name,
            "error_type": detection.error_type,
            "component": detection.component,
            "failure_count": detection.failure_count,
            "sample_errors": detection.sample_errors[:3],
        }

        return WalIssueSignature(
            issue_type="wal_failure",
            error_type=detection.error_type,
            component=detection.component,
            failure_count=detection.failure_count,
            signature_hash=compute_signature_hash(
                "wal", detection.error_type, context
            ),
        )