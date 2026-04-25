"""Main tracker orchestrator for the flywheel system."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import structlog

from flywheel.detectors.base import DetectorResult
from flywheel.detectors.health import HealthDetector
from flywheel.detectors.logs import LogDetector
from flywheel.detectors.splunk import SplunkDetector
from flywheel.detectors.wal import WalDetector
from flywheel.issue_creator import (
    IssueSpec,
    build_investigation_steps,
    create_flywheel_issue,
    get_splunk_link,
)
from flywheel.state import FlywheelState, load_state, save_state

logger = structlog.get_logger("flywheel.tracker")

# Default state file location
DEFAULT_STATE_FILE = "/data/flywheel_state.json"


@dataclass
class TrackerConfig:
    """Configuration for the tracker."""

    interval: int = 60  # seconds between detection cycles
    stability_threshold: float = 0.01  # 1% error rate = stable
    health_url: str = "http://shrike:8080/health"
    wal_dir: str = "/data/wal"
    log_path: str = "/var/log/shrike"
    state_file: str = DEFAULT_STATE_FILE


@dataclass
class TrackerResult:
    """Result of a tracker cycle."""

    cycle_time: float = 0.0
    detections_by_detector: dict[str, int] = field(default_factory=dict)
    issues_by_detector: dict[str, int] = field(default_factory=dict)
    issues_created: list[int] = field(default_factory=list)
    state: Optional[FlywheelState] = None


class FlywheelTracker:
    """Main orchestrator for the flywheel detection system.

    Runs all detectors on a configurable interval, deduplicates across
    detectors, creates issues via issue_creator, and tracks stability metrics.
    """

    name = "flywheel-tracker"

    def __init__(self, config: Optional[TrackerConfig] = None) -> None:
        self._config = config or TrackerConfig()
        self._state: Optional[FlywheelState] = None
        self._last_cycle_time: float = 0

        # Initialize detectors
        self._detectors: list[Any] = [
            HealthDetector(health_url=self._config.health_url),
            WalDetector(wal_dir=self._config.wal_dir),
            LogDetector(log_path=self._config.log_path),
            SplunkDetector(),
        ]

    def run_cycle(self) -> TrackerResult:
        """Run a single detection cycle across all detectors.

        Returns:
            TrackerResult with detections, issues, and state.
        """
        start_time = time.perf_counter()
        cycle_time = datetime.utcnow().isoformat() + "Z"

        logger.info("Starting detection cycle", cycle_time=cycle_time)

        detections_by_detector: dict[str, int] = {}
        issues_by_detector: dict[str, int] = {}
        all_issues: list[Any] = []

        # Run each detector (graceful degradation)
        for detector in self._detectors:
            detector_name = getattr(detector, "name", str(detector.__class__.__name__))

            try:
                result = detector.detect()
                detections_by_detector[detector_name] = len(result.detections)
                issues_by_detector[detector_name] = len(result.issues)
                all_issues.extend(result.issues)
                logger.debug(
                    "Detector completed",
                    detector=detector_name,
                    detections=len(result.detections),
                    issues=len(result.issues),
                )
            except Exception as e:
                logger.warning(
                    "Detector failed, continuing with others",
                    detector=detector_name,
                    error=str(e),
                )

        # Deduplicate issues across detectors
        unique_issues = self._deduplicate_issues(all_issues)

        # Create GitHub issues
        issues_created = self._create_issues(unique_issues)

        # Update state
        self._update_state(
            cycle_time=cycle_time,
            detections_by_detector=detections_by_detector,
            issues_by_detector=issues_by_detector,
            issues_created=len(issues_created),
        )

        elapsed = time.perf_counter() - start_time

        logger.info(
            "Detection cycle complete",
            elapsed_ms=round(elapsed * 1000, 2),
            total_detections=sum(detections_by_detector.values()),
            total_issues=sum(issues_by_detector.values()),
            issues_created=len(issues_created),
        )

        return TrackerResult(
            cycle_time=elapsed,
            detections_by_detector=detections_by_detector,
            issues_by_detector=issues_by_detector,
            issues_created=issues_created,
            state=self._state,
        )

    def _deduplicate_issues(self, issues: list[Any]) -> list[Any]:
        """Deduplicate issues across detectors.

        Issues are considered duplicates if they have the same
        component and similar signature.
        """
        seen: dict[str, Any] = {}
        unique: list[Any] = []

        for issue in issues:
            # Get signature from detector
            if hasattr(issue, "build_signature"):
                sig = issue.build_signature(issue)
                key = f"{sig.component}:{sig.signature_hash}"
            else:
                # Fall back to string representation
                key = str(issue)[:200]

            if key not in seen:
                seen[key] = issue
                unique.append(issue)

        return unique

    def _create_issues(self, issues: list[Any]) -> list[int]:
        """Create GitHub issues for the given issues.

        Returns:
            List of created issue numbers.
        """
        created: list[int] = []

        for issue in issues:
            try:
                spec = self._build_issue_spec(issue)
                issue_num = create_flywheel_issue(spec)
                if issue_num:
                    created.append(issue_num)
            except Exception as e:
                logger.warning("Failed to create issue", error=str(e))

        return created

    def _build_issue_spec(self, issue: Any) -> IssueSpec:
        """Build an IssueSpec from a detection result."""
        # Get component and issue type from detector
        if hasattr(issue, "component"):
            component = issue.component
        elif hasattr(issue, "dest_name"):
            component = issue.dest_name
        else:
            component = "unknown"

        if hasattr(issue, "error_type"):
            issue_type = issue.error_type
        elif hasattr(issue, "issue_type"):
            issue_type = issue.issue_type
        else:
            issue_type = "unknown"

        # Build short description
        if hasattr(issue, "failure_count") and issue.failure_count:
            short_description = f"{issue_type} - {issue.failure_count} failures"
        elif hasattr(issue, "error_count") and issue.error_count:
            short_description = f"{issue_type} - {issue.error_count} errors"
        elif hasattr(issue, "container_status"):
            short_description = f"Container {issue.container_status}"
        elif hasattr(issue, "metric_name"):
            short_description = f"{issue.metric_name} = {issue.metric_value:.2%}"
        else:
            short_description = f"{issue_type} detected"

        # Collect sample data
        sample_data: list[str] = []
        if hasattr(issue, "sample_errors") and issue.sample_errors:
            sample_data.extend(issue.sample_errors)
        if hasattr(issue, "sample_messages") and issue.sample_messages:
            sample_data.extend(issue.sample_messages)
        if hasattr(issue, "docker_state") and issue.docker_state:
            sample_data.append(json.dumps(issue.docker_state))

        # Build investigation steps
        investigation = build_investigation_steps(component, issue_type)

        # Build Splunk link
        splunk_link = get_splunk_link(component)

        return IssueSpec(
            component=component,
            short_description=short_description,
            sample_data=sample_data,
            suggested_investigation=investigation,
            splunk_link=splunk_link,
        )

    def _update_state(
        self,
        cycle_time: str,
        detections_by_detector: dict[str, int],
        issues_by_detector: dict[str, int],
        issues_created: int,
    ) -> None:
        """Update the flywheel state file."""
        # Load existing state
        state = load_state(self._config.state_file)

        # Update metrics
        state.total_events_processed += sum(detections_by_detector.values())
        state.last_cycle_time = cycle_time

        # Update issues by component
        for component, count in issues_by_detector.items():
            if component not in state.issues_by_component:
                state.issues_by_component[component] = 0
            state.issues_by_component[component] += count

        # Update issues created
        state.total_issues_created += issues_created

        # Calculate rolling error rate
        if state.total_events_processed > 0:
            total_issues = sum(state.issues_by_component.values())
            state.error_rate_7day = total_issues / state.total_events_processed

        # Update stability status
        if state.error_rate_7day < self._config.stability_threshold:
            state.consecutive_stable_days += 1
            if state.consecutive_stable_days >= 7:
                state.stability_status = "STABLE"
        else:
            state.consecutive_stable_days = 0
            state.stability_status = "DEGRADED"

        # Save state
        save_state(state, self._config.state_file)
        self._state = state

    def run(self) -> None:
        """Run the tracker continuously."""
        logger.info(
            "Starting flywheel tracker",
            interval=self._config.interval,
            detectors=len(self._detectors),
        )

        while True:
            try:
                self.run_cycle()
            except Exception as e:
                logger.error("Cycle failed", error=str(e))

            time.sleep(self._config.interval)