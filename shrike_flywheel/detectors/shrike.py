"""Shrike-specific health detector.

Extends HTTPHealthDetector with Docker inspect for OOM/restart
detection. Shrike-specific — not reusable without modification.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Optional

import structlog

from flywheel.detectors.base import DetectorResult, compute_signature_hash
from flywheel.detectors.http import HTTPHealthDetector

logger = structlog.get_logger("shrike_flywheel.detectors.shrike")

# Container name
CONTAINER_NAME = "shrike"


class ShrikeHealthDetector(HTTPHealthDetector):
    """Shrike-specific health detector.

    Extends HTTPHealthDetector with:
    - Docker inspect for OOM detection
    - Restart count tracking
    """

    name = "shrike_health"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        base_url: str = "http://shrike:8080",
        health_endpoint: str = "/health",
        latency_threshold_ms: float = 500,
        container_name: str = CONTAINER_NAME,
    ) -> None:
        """Initialize Shrike health detector.

        Args:
            config: FlywheelConfig detector config
            base_url: Base URL of the service
            health_endpoint: Health check endpoint path
            latency_threshold_ms: Max acceptable latency in ms
            container_name: Docker container name
        """
        super().__init__(
            config=config,
            base_url=base_url,
            health_endpoint=health_endpoint,
            latency_threshold_ms=latency_threshold_ms,
        )
        self._container_name = container_name
        self._last_restart_count: int = 0
        self._last_container_state: dict | None = None

    def detect(self) -> DetectorResult | None:
        """Run Shrike-specific health checks.

        Checks HTTP health AND docker inspect for OOM/restart.

        Returns:
            DetectorResult if any issue found, None otherwise
        """
        # Check HTTP health (parent)
        http_result = super().detect()
        if http_result:
            return http_result

        # Check docker inspect
        docker_result = self._check_docker_inspect()
        if docker_result:
            return docker_result

        return None

    def _check_docker_inspect(self) -> Optional[DetectorResult]:
        """Inspect Docker container for OOM and restart events."""
        try:
            result = subprocess.run(
                ["sudo", "docker", "inspect", self._container_name],
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

            oom_killed = state.get("OOMKilled", False)
            restart_count = state.get("RestartCount", 0)
            running = state.get("Running", False)

            # Detect restart if count increased
            restart_detected = restart_count > self._last_restart_count
            self._last_restart_count = restart_count
            self._last_container_state = container_info

            if oom_killed:
                return DetectorResult(
                    name=self.name,
                    is_issue=True,
                    title=f"[health] {self._container_name} OOM killed",
                    body=f"Container was OOM killed. Restart count: {restart_count}",
                    labels=["health", "oom", "flywheel-candidate"],
                    signature=compute_signature_hash(
                        "shrike_health",
                        "oom",
                        {"container": self._container_name},
                    ),
                    severity="high",
                    component="health",
                    metadata={"restart_count": restart_count, "oom_killed": True},
                )

            if restart_detected:
                return DetectorResult(
                    name=self.name,
                    is_issue=True,
                    title=f"[health] {self._container_name} restarted",
                    body=f"Container restarted. Restart count: {restart_count}",
                    labels=["health", "restart", "flywheel-candidate"],
                    signature=compute_signature_hash(
                        "shrike_health",
                        "restart",
                        {"container": self._container_name, "restart_count": restart_count},
                    ),
                    severity="medium",
                    component="health",
                    metadata={"restart_count": restart_count},
                )

            return None

        except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError) as e:
            logger.warning("Docker inspect failed", error=str(e))
            return None