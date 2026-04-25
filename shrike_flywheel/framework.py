"""Shrike-specific flywheel framework.

Extends FlywheelFramework with Shrike-specific detectors:
- ShrikeHealthDetector (HTTP + Docker inspect)
- WalDetector (WAL file monitoring)
- ShrikeLogDetector (structured log parsing)
- SplunkDetector (Splunk metric queries)
"""

from __future__ import annotations

from typing import Any

import structlog

from flywheel.config import FlywheelConfig
from flywheel.detectors.base import Detector
from flywheel.framework import FlywheelFramework

logger = structlog.get_logger("shrike_flywheel.framework")


class ShrikeFlywheelFramework(FlywheelFramework):
    """Shrike-specific flywheel framework.

    Loads Shrike-specific detectors and runs them on interval.
    """

    name = "shrike-flywheel"

    def _load_detectors(self) -> dict[str, Detector]:
        """Load Shrike-specific detectors.

        Returns:
            Dict of name -> Detector instance
        """
        detectors: dict[str, Detector] = {}

        # Shrike health detector (HTTP + Docker inspect)
        if self.config.is_detector_enabled("health"):
            from shrike_flywheel.detectors.shrike import ShrikeHealthDetector

            det_config = self.config.detector_config("health")
            detectors["health"] = ShrikeHealthDetector(
                config=det_config.thresholds if det_config else {},
                base_url=self.config.api.base_url,
                health_endpoint=self.config.api.health_endpoint,
                latency_threshold_ms=self.config.threshold(
                    "health", "latency_ms", 500
                ),
            )

        # WAL detector
        if self.config.is_detector_enabled("wal"):
            from shrike_flywheel.detectors.wal import WalDetector

            det_config = self.config.detector_config("wal")
            detectors["wal"] = WalDetector(
                config=det_config.thresholds if det_config else {},
                wal_dir=self.config.threshold("wal", "path", "/data/wal"),
                failure_threshold=self.config.threshold("wal", "failure_count", 5),
                window_minutes=self.config.threshold("wal", "window_minutes", 10),
            )

        # Log detector
        if self.config.is_detector_enabled("logs"):
            from shrike_flywheel.detectors.logs import ShrikeLogDetector

            det_config = self.config.detector_config("logs")
            detectors["logs"] = ShrikeLogDetector(
                config=det_config.thresholds if det_config else {},
                log_path=self.config.threshold("logs", "path", "/data/shrike.log"),
                error_threshold=self.config.threshold("logs", "error_count", 3),
                window_minutes=self.config.threshold("logs", "window_minutes", 5),
            )

        # Splunk detector
        if self.config.is_detector_enabled("splunk"):
            from shrike_flywheel.detectors.splunk import SplunkDetector

            det_config = self.config.detector_config("splunk")
            detectors["splunk"] = SplunkDetector(
                config=det_config.thresholds if det_config else {},
                error_rate_threshold=self.config.threshold(
                    "splunk", "error_rate", 0.05
                ),
                window_minutes=self.config.threshold("splunk", "window_minutes", 10),
            )

        logger.info(
            "Loaded detectors",
            detectors=list(detectors.keys()),
        )

        return detectors