"""WAL file detector for Shrike.

Monitors Shrike's WAL directory for failed events.
Shrike-specific — not reusable without modification.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import structlog

from flywheel.detectors.base import Detector, DetectorResult, compute_signature_hash

logger = structlog.get_logger("shrike_flywheel.detectors.wal")


class WalDetector(Detector):
    """WAL failure detector for Shrike.

    Monitors /data/wal for failed events:
    - New WAL files appearing = extraction/routing failure
    - Parse WAL, extract error type, classify by component
    - Threshold: >N failures in window = issue
    """

    name = "wal"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        wal_dir: str = "/data/wal",
        failure_threshold: int = 5,
        window_minutes: int = 10,
    ) -> None:
        """Initialize WAL detector.

        Args:
            config: FlywheelConfig detector config
            wal_dir: Path to WAL directory
            failure_threshold: Max failures before issue
            window_minutes: Time window to analyze
        """
        super().__init__(config)
        self._wal_dir = Path(wal_dir)
        self._failure_threshold = failure_threshold
        self._window_seconds = window_minutes * 60
        self._last_check_time: float = 0
        self._last_known_files: dict[str, float] = {}

    def detect(self) -> DetectorResult | None:
        """Scan WAL directory for failures.

        Returns:
            DetectorResult if threshold exceeded, None otherwise
        """
        if not self.should_run(30):  # Minimum 30s between runs
            return None

        if not self._wal_dir.is_dir():
            logger.warning("WAL directory not accessible", wal_dir=str(self._wal_dir))
            return None

        failures: list[dict] = []
        sample_errors: list[str] = []

        # Check for WAL files
        for wal_path in self._wal_dir.glob("*.wal.jsonl"):
            detection = self._scan_wal_file(wal_path)
            if detection:
                failures.extend(detection.get("failures", []))
                sample_errors.extend(detection.get("samples", [])[:3])

        if len(failures) > self._failure_threshold:
            # Classify failures
            error_type, component = self._classify_failures(failures)

            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[wal] {len(failures)} WAL failures in last {self._window_seconds // 60} minutes",
                body=self._build_body(failures, sample_errors, error_type, component),
                labels=["wal", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "wal",
                    "failure_count",
                    {
                        "failure_count": len(failures),
                        "window_minutes": self._window_seconds // 60,
                    },
                ),
                severity="high",
                component=component,
                metadata={
                    "failure_count": len(failures),
                    "error_type": error_type,
                    "samples": sample_errors[:5],
                },
            )

        return None

    def _scan_wal_file(self, wal_path: Path) -> Optional[dict[str, Any]]:
        """Scan a WAL file for failed events."""
        try:
            stat = wal_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size

            # Skip if file hasn't changed
            last_size = self._last_known_files.get(wal_path.name, 0)
            if size <= last_size and mtime < time.time() - self._window_seconds:
                return None

            self._last_known_files[wal_path.name] = size

            failures: list[dict] = []
            samples: list[str] = []

            with open(wal_path, "r") as f:
                lines = f.readlines()[-1000:] if stat.st_size > 100_000 else f.readlines()

            cutoff = time.time() - self._window_seconds
            for line in lines:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if self._is_failure_event(event):
                        failures.append(event)
                        if len(samples) < 5:
                            samples.append(self._extract_error(event))
                except json.JSONDecodeError:
                    continue

            return {"failures": failures, "samples": samples}
        except OSError as e:
            logger.warning("Failed to scan WAL file", path=str(wal_path), error=str(e))
            return None

    def _is_failure_event(self, event: dict) -> bool:
        """Check if a WAL event represents a failure."""
        if event.get("_shrike_failure") or event.get("failed"):
            return True
        status = event.get("status", "")
        if status in ("failed", "error", "rejected"):
            return True
        retry_count = event.get("retry_count", 0)
        if retry_count >= 3:
            return True
        return False

    def _extract_error(self, event: dict) -> str:
        """Extract error message from event."""
        if event.get("error"):
            return str(event["error"])[:200]
        if event.get("error_message"):
            return str(event["error_message"])[:200]
        if event.get("message"):
            return str(event["message"])[:200]
        raw = event.get("raw_event", "")
        if raw:
            return raw[:200]
        return json.dumps(event)[:200]

    def _classify_failures(self, failures: list[dict]) -> tuple[str, str]:
        """Classify failures by component and error type."""
        components: list[str] = []
        error_types: list[str] = []

        for event in failures:
            ocsf_class = event.get("class_name", "") or event.get("category_uid", "")
            if ocsf_class:
                components.append(str(ocsf_class))

            error_type = event.get("error_type", "") or event.get("status", "unknown")
            error_types.append(str(error_type))

        component_counter = Counter(components)
        error_type_counter = Counter(error_types)

        most_common_component = component_counter.most_common(1)[0][0] if component_counter else "unknown"
        most_common_error = error_type_counter.most_common(1)[0][0] if error_type_counter else "unknown"

        return most_common_error, most_common_component

    def _build_body(
        self,
        failures: list[dict],
        samples: list[str],
        error_type: str,
        component: str,
    ) -> str:
        """Build markdown body for WAL issue."""
        lines = [
            f"Found {len(failures)} WAL failures in the last {self._window_seconds // 60} minutes:",
            "",
            f"**Error type**: {error_type}",
            f"**Component**: {component}",
            "",
            "## Sample Errors",
            "",
        ]
        for i, sample in enumerate(samples[:10], 1):
            lines.append(f"{i}. ```")
            lines.append(f"   {sample}")
            lines.append(f"   ```")
        lines.append("")
        lines.append(f"*WAL directory: {self._wal_dir}*")
        return "\n".join(lines)