"""YAML config schema for the flywheel framework.

Defines the declarative config format used to configure the flywheel
framework for any project. All thresholds, endpoints, and options are
driven by this config — no code changes needed to tune behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ProjectConfig:
    """Project identification."""

    name: str = "unknown"
    github_repo: str = ""
    github_token_env: str = "GITHUB_TOKEN"


@dataclass
class APIConfig:
    """API endpoint configuration."""

    base_url: str = "http://localhost:8080"
    health_endpoint: str = "/health"
    ingest_endpoint: str = "/v1/ingest"


@dataclass
class DetectorThresholdConfig:
    """Threshold values for a detector."""

    latency_ms: float = 500
    failure_count: int = 5
    window_minutes: int = 10
    error_count: int = 3
    error_rate: float = 0.05


@dataclass
class DetectorConfig:
    """Configuration for a single detector."""

    enabled: bool = True
    interval: int = 30
    thresholds: dict[str, Any] = field(default_factory=dict)


@dataclass
class StabilityConfig:
    """Stability criteria."""

    error_rate_threshold: float = 0.01
    consecutive_days: int = 7


@dataclass
class IssueConfig:
    """GitHub issue creation settings."""

    labels: list[str] = field(default_factory=lambda: ["flywheel-candidate", "customer-zero"])
    dedup_window_hours: int = 24


@dataclass
class FlywheelConfig:
    """Root flywheel configuration.

    Loaded from a YAML file. Drives all framework behavior —
    detectors, thresholds, API endpoints, and issue creation.
    """

    project: ProjectConfig = field(default_factory=ProjectConfig)
    api: APIConfig = field(default_factory=APIConfig)
    detectors: dict[str, DetectorConfig] = field(default_factory=dict)
    stability: StabilityConfig = field(default_factory=StabilityConfig)
    issue: IssueConfig = field(default_factory=IssueConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "FlywheelConfig":
        """Load config from a YAML file.

        Args:
            path: Path to the config YAML file

        Returns:
            FlywheelConfig instance
        """
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not data:
            return cls()

        # Parse project
        project_data = data.get("project", {})
        project = ProjectConfig(
            name=project_data.get("name", "unknown"),
            github_repo=project_data.get("github_repo", ""),
            github_token_env=project_data.get("github_token_env", "GITHUB_TOKEN"),
        )

        # Parse API config
        api_data = data.get("api", {})
        api = APIConfig(
            base_url=api_data.get("base_url", "http://localhost:8080"),
            health_endpoint=api_data.get("health_endpoint", "/health"),
            ingest_endpoint=api_data.get("ingest_endpoint", "/v1/ingest"),
        )

        # Parse detectors
        detectors: dict[str, DetectorConfig] = {}
        for name, det_data in data.get("detectors", {}).items():
            thresholds = det_data.get("thresholds", {})
            detectors[name] = DetectorConfig(
                enabled=det_data.get("enabled", True),
                interval=det_data.get("interval", 30),
                thresholds=thresholds,
            )

        # Parse stability
        stability_data = data.get("stability", {})
        stability = StabilityConfig(
            error_rate_threshold=stability_data.get("error_rate_threshold", 0.01),
            consecutive_days=stability_data.get("consecutive_days", 7),
        )

        # Parse issue config
        issue_data = data.get("issue", {})
        issue = IssueConfig(
            labels=issue_data.get("labels", ["flywheel-candidate", "customer-zero"]),
            dedup_window_hours=issue_data.get("dedup_window_hours", 24),
        )

        return cls(
            project=project,
            api=api,
            detectors=detectors,
            stability=stability,
            issue=issue,
        )

    def detector_config(self, name: str) -> DetectorConfig | None:
        """Get config for a named detector.

        Args:
            name: Detector name

        Returns:
            DetectorConfig or None if not configured
        """
        return self.detectors.get(name)

    def is_detector_enabled(self, name: str) -> bool:
        """Check if a detector is enabled.

        Args:
            name: Detector name

        Returns:
            True if enabled (defaults to True if not configured)
        """
        config = self.detectors.get(name)
        if config is None:
            return True  # Default to enabled
        return config.enabled

    def threshold(self, detector: str, key: str, default: Any = None) -> Any:
        """Get a threshold value for a detector.

        Args:
            detector: Detector name
            key: Threshold key (e.g., "latency_ms", "failure_count")
            default: Default value if not found

        Returns:
            Threshold value or default
        """
        config = self.detectors.get(detector)
        if config is None:
            return default
        return config.thresholds.get(key, default)