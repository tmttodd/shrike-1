"""Health detector — polls Shrike /health endpoint and tracks container health."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
import structlog

from flywheel.detectors.base import Detection, DetectorResult, IssueSignature

logger = structlog.get_logger("flywheel.detector.health")

# Threshold for latency spike detection (milliseconds)
LATENCY_THRESHOLD_MS = 500

# Container name to inspect
CONTAINER_NAME = "shrike"


@dataclass
class HealthIssueSignature(IssueSignature):
    """Signature for health-related issues."""

    issue_type: str = ""  # "unhealthy", "latency_spike", "oom", "restart"
    latency_ms: Optional[float] = None
    docker_inspect: dict = field(default_factory=dict)


@dataclass
class HealthDetection(Detection):
    """A single health detection result."""

    container_status: str = "unknown"  # "healthy", "unhealthy", "unknown"
    latency_ms: float = 0.0
    oom_detected: bool = False
    restart_detected: bool = False
    docker_state: dict = field(default_factory=dict)


class HealthDetector:
    """Detect Shrike container and HTTP health issues.

    Polls the /health endpoint every interval and tracks:
    - Container health status (unhealthy = issue)
    - HTTP latency spikes (>500ms = issue)
    - OOM/restart events from docker inspect
    """

    name = "health"

    def __init__(
        self,
        health_url: str = "http://shrike:8080/health",
        interval: int = 30,
        latency_threshold_ms: int = LATENCY_THRESHOLD_MS,
    ) -> None:
        self._health_url = health_url
        self._interval = interval
        self._latency_threshold_ms = latency_threshold_ms
        self._last_check_time: float = 0
        self._last_container_state: Optional[dict] = None

    def detect(self) -> DetectorResult:
        """Run a single detection cycle. Returns issues found."""
        now = time.time()
        if now - self._last_check_time < self._interval:
            return DetectorResult(detections=[], issues=[])

        self._last_check_time = now
        detections: list[HealthDetection] = []
        issues: list[HealthDetection] = []

        # Check HTTP health endpoint
        http_detection = self._check_http_health()
        if http_detection:
            detections.append(http_detection)
            if http_detection.container_status == "unhealthy":
                issues.append(http_detection)
            elif http_detection.latency_ms > self._latency_threshold_ms:
                issues.append(http_detection)

        # Check docker inspect for OOM/restart
        docker_detection = self._check_docker_inspect()
        if docker_detection:
            detections.append(docker_detection)
            if docker_detection.oom_detected or docker_detection.restart_detected:
                issues.append(docker_detection)

        return DetectorResult(detections=detections, issues=issues)

    def _check_http_health(self) -> Optional[HealthDetection]:
        """Poll the /health endpoint and measure latency."""
        start = time.perf_counter()
        try:
            response = requests.get(self._health_url, timeout=5)
            latency_ms = (time.perf_counter() - start) * 1000
        except requests.RequestException as e:
            logger.warning("Health check failed", error=str(e))
            return HealthDetection(
                container_status="unreachable",
                latency_ms=0,
                docker_state={},
            )

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.warning("Invalid health response", status=response.status_code)
            return HealthDetection(container_status="unknown", latency_ms=latency_ms)

        status = data.get("status", "unknown")
        return HealthDetection(
            container_status=status,
            latency_ms=latency_ms,
            docker_state={},
        )

    def _check_docker_inspect(self) -> Optional[HealthDetection]:
        """Inspect docker container for OOM and restart events."""
        try:
            result = subprocess.run(
                ["sudo", "docker", "inspect", CONTAINER_NAME],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            inspect_data = json.loads(result.stdout)
            if not inspect_data:
                return None

            container_info = inspect_data[0]
            state = container_info.get("State", {})
            config = container_info.get("Config", {})

            oom_killed = state.get("OOMKilled", False)
            restart_count = state.get("RestartCount", 0)
            running = state.get("Running", False)

            # Detect restart if restart count increased
            restart_detected = False
            if self._last_container_state is not None:
                last_restart_count = self._last_container_state.get("State", {}).get(
                    "RestartCount", 0
                )
                restart_detected = restart_count > last_restart_count

            self._last_container_state = container_info

            return HealthDetection(
                container_status="healthy" if running else "stopped",
                latency_ms=0,
                oom_detected=bool(oom_killed),
                restart_detected=restart_detected,
                docker_state={
                    "oom_killed": oom_killed,
                    "restart_count": restart_count,
                    "running": running,
                    "exit_code": state.get("ExitCode", 0),
                },
            )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError) as e:
            logger.warning("Docker inspect failed", error=str(e))
            return None

    def build_signature(self, detection: HealthDetection) -> HealthIssueSignature:
        """Build an issue signature from a health detection."""
        if detection.oom_detected:
            issue_type = "oom"
        elif detection.restart_detected:
            issue_type = "restart"
        elif detection.container_status == "unhealthy":
            issue_type = "unhealthy"
        elif detection.latency_ms > self._latency_threshold_ms:
            issue_type = "latency_spike"
        else:
            issue_type = detection.container_status

        return HealthIssueSignature(
            issue_type=issue_type,
            latency_ms=detection.latency_ms if detection.latency_ms > 0 else None,
            docker_inspect=detection.docker_state,
        )