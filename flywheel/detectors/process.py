"""Generic log file detector for the flywheel framework.

Works for any project that writes structured logs. Configured entirely
via FlywheelConfig — just set log path and thresholds.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import structlog

from flywheel.detectors.base import Detector, DetectorResult, compute_signature_hash

logger = structlog.get_logger("flywheel.detectors.process")

# Default patterns for ERROR level detection
ERROR_LEVEL_PATTERNS = re.compile(
    r"\b(ERROR|ERR|CRITICAL|FATAL|FAILURE)\b",
    re.IGNORECASE,
)


class ProcessLogDetector(Detector):
    """Generic log file detector.

    Tails a log file and counts ERROR-level entries within a time
    window. Returns DetectorResult if threshold exceeded.

    Works for any project with structured logs — just configure
    log path and thresholds.
    """

    name = "process_log"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        log_path: str = "/data/app.log",
        error_threshold: int = 3,
        window_minutes: int = 5,
    ) -> None:
        """Initialize log detector.

        Args:
            config: FlywheelConfig detector config
            log_path: Path to the log file
            error_threshold: Max errors in window before issue
            window_minutes: Time window to analyze
        """
        super().__init__(config)
        self._log_path = Path(log_path)
        self._error_threshold = error_threshold
        self._window_seconds = window_minutes * 60
        self._last_position: int = 0

    def detect(self) -> DetectorResult | None:
        """Scan log file for ERROR entries in time window.

        Returns:
            DetectorResult if error threshold exceeded, None otherwise
        """
        if not self._log_path.is_file():
            logger.debug("Log file not found", path=str(self._log_path))
            return None

        try:
            stat = self._log_path.stat()
            current_size = stat.st_size
        except OSError as e:
            logger.warning("Cannot stat log file", path=str(self._log_path), error=str(e))
            return None

        # Handle log rotation
        if current_size < self._last_position:
            self._last_position = 0

        errors: list[str] = []
        cutoff = time.time() - self._window_seconds

        try:
            with open(self._log_path, "r") as f:
                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = current_size
        except OSError as e:
            logger.warning("Cannot read log file", path=str(self._log_path), error=str(e))
            return None

        if not new_lines:
            return None

        for line in new_lines:
            if not line.strip():
                continue

            # Parse log line
            parsed = self._parse_line(line)
            if not parsed:
                continue

            # Check for ERROR level
            level = parsed.get("level", "").upper()
            if level not in ("ERROR", "ERR", "CRITICAL", "FATAL"):
                continue

            # Check timestamp
            timestamp = parsed.get("timestamp", "")
            if timestamp:
                try:
                    ts = timestamp.replace("Z", "")
                    line_time = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
                    if line_time < cutoff:
                        continue
                except (ValueError, OSError):
                    pass

            errors.append(parsed.get("message", line)[:200])

        if len(errors) > self._error_threshold:
            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[logs] {len(errors)} errors in last {self._window_seconds // 60} minutes",
                body=self._build_body(errors),
                labels=["logs", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "process_log",
                    "error_count",
                    {"error_count": len(errors), "window_minutes": self._window_seconds // 60},
                ),
                severity="medium",
                component="logs",
                metadata={"error_count": len(errors), "samples": errors[:5]},
            )

        return None

    def _parse_line(self, line: str) -> dict[str, Any]:
        """Parse a log line (JSON or plain text).

        Args:
            line: Raw log line

        Returns:
            Parsed dict with at least "message" key
        """
        line = line.strip()
        if not line:
            return {}

        # Try JSON
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Try syslog format
        syslog_pattern = re.compile(r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+[\d]+:\s+(.*)$")
        match = syslog_pattern.match(line)
        if match:
            return {"timestamp": match.group(1), "message": match.group(2)}

        # Plain text
        return {"message": line}

    def _build_body(self, errors: list[str]) -> str:
        """Build markdown body for log issue.

        Args:
            errors: List of error messages

        Returns:
            Markdown formatted body
        """
        lines = [
            f"Found {len(errors)} errors in the last {self._window_seconds // 60} minutes:",
            "",
        ]
        for i, error in enumerate(errors[:10], 1):
            lines.append(f"{i}. ```")
            lines.append(f"   {error}")
            lines.append(f"   ```")
        lines.append("")
        lines.append(f"*Log file: {self._log_path}*")
        return "\n".join(lines)