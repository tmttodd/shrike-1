"""FlywheelFramework — generic orchestrator for the flywheel system.

Runs all enabled detectors on a configurable interval, deduplicates
across detectors, creates issues via GitHub, and tracks stability.
Works for any project — no project-specific code.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

import structlog

from flywheel.config import FlywheelConfig
from flywheel.detectors.base import Detector, DetectorResult
from flywheel.detectors.github import GitHubClient
from flywheel.state import FlywheelState, load_state, save_state

logger = structlog.get_logger("flywheel.framework")


class FlywheelFramework:
    """Generic flywheel orchestrator.

    Loads config from YAML, runs detectors on interval, creates GitHub
    issues for findings, and tracks stability metrics.

    Deployment phases:
    - DEPLOYING: Initial deployment validation
    - FIRST_RUN: First-run window
    - RUNNING: Normal tracking
    - STABLE: <error_rate_threshold for consecutive_days
    """

    name = "flywheel-framework"

    def __init__(
        self,
        config: FlywheelConfig,
        state_path: str | None = None,
    ) -> None:
        """Initialize flywheel framework.

        Args:
            config: FlywheelConfig instance
            state_path: Path for state file (default: /data/{project}_flywheel_state.json)
        """
        self.config = config
        self.project_name = config.project.name

        # Default state path
        if state_path is None:
            state_path = f"/data/{self.project_name}_flywheel_state.json"

        self._state_path = state_path
        self._state: Optional[FlywheelState] = None

        # GitHub client
        if config.project.github_repo:
            self._github = GitHubClient(
                github_repo=config.project.github_repo,
                github_token_env=config.project.github_token_env,
            )
        else:
            self._github = None

        # Detectors (loaded by subclass)
        self._detectors: dict[str, Detector] = {}

        # Interval from config (default 60s)
        self._interval = 60

    @property
    def state(self) -> FlywheelState:
        """Get current state (lazy load)."""
        if self._state is None:
            self._state = load_state(self._state_path)
        return self._state

    def _load_detectors(self) -> dict[str, Detector]:
        """Load all enabled detectors.

        Override in subclass to add project-specific detectors.
        Default implementation uses config to determine which detectors
        to load.

        Returns:
            Dict of name -> Detector instance
        """
        detectors: dict[str, Detector] = {}

        # HTTP health detector
        if self.config.is_detector_enabled("health"):
            from flywheel.detectors.http import HTTPHealthDetector

            det_config = self.config.detector_config("health")
            detectors["health"] = HTTPHealthDetector(
                config=det_config.thresholds if det_config else {},
                base_url=self.config.api.base_url,
                health_endpoint=self.config.api.health_endpoint,
                latency_threshold_ms=self.config.threshold(
                    "health", "latency_ms", 500
                ),
            )

        # Process log detector
        if self.config.is_detector_enabled("logs"):
            from flywheel.detectors.process import ProcessLogDetector

            det_config = self.config.detector_config("logs")
            detectors["logs"] = ProcessLogDetector(
                config=det_config.thresholds if det_config else {},
                log_path=self.config.threshold("logs", "path", "/data/app.log"),
                error_threshold=self.config.threshold("logs", "error_count", 3),
                window_minutes=self.config.threshold("logs", "window_minutes", 5),
            )

        return detectors

    def run_once(self) -> list[DetectorResult]:
        """Run all enabled detectors once.

        Returns:
            List of DetectorResult for issues found
        """
        results: list[DetectorResult] = []

        for name, detector in self._detectors.items():
            try:
                result = detector.detect()
                if result and result.is_issue:
                    results.append(result)
                    self._handle_result(result)
            except Exception as e:
                logger.error(
                    f"Detector {name} failed",
                    exc=e,
                    detector=name,
                )

        self.state.record_run()
        save_state(self.state, self._state_path)
        return results

    def _handle_result(self, result: DetectorResult) -> None:
        """Handle a detector result — create issue or update state.

        Args:
            result: DetectorResult from a detector
        """
        # Check for duplicate
        if self._is_duplicate(result):
            logger.debug(
                "Duplicate detected, skipping",
                component=result.component,
                signature=result.signature,
            )
            return

        # Create GitHub issue
        if self._github and result.is_issue:
            try:
                issue = self._github.create_issue(
                    title=result.title,
                    body=result.body,
                    labels=result.labels,
                )
                if issue:
                    self.state.record_issue(result.component, issue.number)
                    save_state(self.state, self._state_path)
                    logger.info(
                        "Created issue",
                        number=issue.number,
                        component=result.component,
                    )
            except Exception as e:
                logger.error(
                    "Failed to create issue",
                    component=result.component,
                    error=str(e),
                )
        else:
            # Just record the detection
            self.state.record_detection(result.component)

    def _is_duplicate(self, result: DetectorResult) -> bool:
        """Check if this result is a duplicate of a recent issue.

        Args:
            result: DetectorResult to check

        Returns:
            True if duplicate found
        """
        if not self._github:
            return False

        # Extract title prefix for comparison
        title_prefix = result.title.split("]")[0] + "]" if "]" in result.title else result.title[:50]

        existing = self._github.find_duplicate(
            title_prefix=title_prefix,
            hours=self.config.issue.dedup_window_hours,
        )
        return existing is not None

    def run_until_stable(self) -> None:
        """Run detection cycles until stability is achieved.

        Runs indefinitely, checking stability after each cycle.
        """
        logger.info(
            "Starting flywheel",
            project=self.project_name,
            interval=self._interval,
            detectors=list(self._detectors.keys()),
        )

        # Set initial phase
        if self.state.phase == "DEPLOYING":
            self.state.set_phase("DEPLOYING")
            save_state(self.state, self._state_path)

        while True:
            try:
                results = self.run_once()

                # Check stability
                if self.state.is_stable(
                    error_rate_threshold=self.config.stability.error_rate_threshold,
                    consecutive_days=self.config.stability.consecutive_days,
                ):
                    logger.info(
                        "Stability achieved",
                        consecutive_days=self.state.consecutive_stable_days,
                        error_rate=self.state.error_rate,
                    )
                    break

                # Increment stable days if no issues
                if not results and self.state.phase == "RUNNING":
                    self.state.increment_stable_days()
                    save_state(self.state, self._state_path)

            except Exception as e:
                logger.error("Cycle failed", error=str(e))

            time.sleep(self._interval)

    def run(self, cycles: int | None = None) -> None:
        """Run detection cycles.

        Args:
            cycles: Number of cycles to run (None = infinite)
        """
        logger.info(
            "Starting flywheel",
            project=self.project_name,
            interval=self._interval,
            detectors=list(self._detectors.keys()),
        )

        count = 0
        while cycles is None or count < cycles:
            try:
                self.run_once()
            except Exception as e:
                logger.error("Cycle failed", error=str(e))

            count += 1
            time.sleep(self._interval)