"""Structured log detector for Shrike.

Parses Shrike's structured logs for ERROR level entries.
Shrike-specific — not reusable without modification.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

import structlog

from flywheel.detectors.base import Detector, DetectorResult, compute_signature_hash

logger = structlog.get_logger("shrike_flywheel.detectors.logs")

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


class ShrikeLogDetector(Detector):
    """Structured log detector for Shrike.

    Parses Shrike's structured logs:
    - ERROR level logs = issue
    - Classify by component
    - Threshold: >N errors in window = issue
    """

    name = "shrike_logs"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        log_path: str = "/data/shrike.log",
        error_threshold: int = 3,
        window_minutes: int = 5,
    ) -> None:
        """Initialize log detector.

        Args:
            config: FlywheelConfig detector config
            log_path: Path to the log file
            error_threshold: Max errors before issue
            window_minutes: Time window to analyze
        """
        super().__init__(config)
        self._log_path = Path(log_path)
        self._error_threshold = error_threshold
        self._window_seconds = window_minutes * 60
        self._last_position: int = 0

    def detect(self) -> DetectorResult | None:
        """Scan log file for ERROR entries.

        Returns:
            DetectorResult if threshold exceeded, None otherwise
        """
        if not self.should_run(30):
            return None

        # Try common log locations
        for log_path in [
            self._log_path,
            Path("/var/log/shrike.log"),
            Path("/data/shrike.log"),
            Path("/data/logs/shrike.log"),
        ]:
            if not log_path.is_file():
                continue

            result = self._scan_log_file(log_path)
            if result:
                return result
            break

        return None

    def _scan_log_file(self, log_path: Path) -> Optional[DetectorResult]:
        """Scan a log file for ERROR level entries."""
        try:
            stat = log_path.stat()
            current_size = stat.st_size

            # Handle log rotation
            if current_size < self._last_position:
                self._last_position = 0

            with open(log_path, "r") as f:
                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = current_size

            if not new_lines:
                return None

            cutoff = time.time() - self._window_seconds
            errors_by_component: dict[str, list[str]] = {}

            for line in new_lines:
                if not line.strip():
                    continue

                parsed = self._parse_line(line)
                if not parsed:
                    continue

                # Check for ERROR level
                level = parsed.get("level", "").upper()
                if level not in ("ERROR", "ERR", "CRITICAL", "FATAL"):
                    continue

                # Check timestamp
                timestamp_str = parsed.get("timestamp", "")
                if timestamp_str:
                    try:
                        ts = timestamp_str.replace("Z", "")
                        line_time = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
                        if line_time < cutoff:
                            continue
                    except (ValueError, OSError):
                        pass

                component = self._classify_component(parsed.get("message", ""))
                error_msg = parsed.get("message", line[:200])

                if component not in errors_by_component:
                    errors_by_component[component] = []
                if len(errors_by_component[component]) < 5:
                    errors_by_component[component].append(error_msg)

            if not errors_by_component:
                return None

            total_errors = sum(len(msgs) for msgs in errors_by_component.values())
            if total_errors > self._error_threshold:
                primary_component = max(
                    errors_by_component, key=lambda c: len(errors_by_component[c])
                )
                sample_messages = errors_by_component[primary_component]

                return DetectorResult(
                    name=self.name,
                    is_issue=True,
                    title=f"[logs] {total_errors} errors in last {self._window_seconds // 60} minutes",
                    body=self._build_body(errors_by_component),
                    labels=["logs", "flywheel-candidate"],
                    signature=compute_signature_hash(
                        "shrike_logs",
                        "error_count",
                        {
                            "error_count": total_errors,
                            "window_minutes": self._window_seconds // 60,
                        },
                    ),
                    severity="medium",
                    component=primary_component,
                    metadata={
                        "error_count": total_errors,
                        "samples": sample_messages,
                    },
                )

            return None

        except OSError as e:
            logger.warning("Failed to scan log file", path=str(log_path), error=str(e))
            return None

    def _parse_line(self, line: str) -> dict[str, Any]:
        """Parse a log line (JSON or plain text)."""
        line = line.strip()
        if not line:
            return {}

        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Syslog format
        syslog_pattern = re.compile(r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+[\d]+:\s+(.*)$")
        match = syslog_pattern.match(line)
        if match:
            return {"timestamp": match.group(1), "message": match.group(2)}

        return {"message": line}

    def _classify_component(self, message: str) -> str:
        """Classify a log message by component."""
        for component, pattern in COMPONENT_PATTERNS.items():
            if pattern.search(message):
                return component
        return "unknown"

    def _build_body(self, errors_by_component: dict[str, list[str]]) -> str:
        """Build markdown body for log issue."""
        lines = [
            f"Found {sum(len(msgs) for msgs in errors_by_component.values())} errors in the last {self._window_seconds // 60} minutes:",
            "",
        ]
        for component, messages in errors_by_component.items():
            lines.append(f"### {component}")
            lines.append("")
            for i, msg in enumerate(messages[:5], 1):
                lines.append(f"{i}. ```")
                lines.append(f"   {msg}")
                lines.append(f"   ```")
            lines.append("")
        lines.append(f"*Log file: {self._log_path}*")
        return "\n".join(lines)