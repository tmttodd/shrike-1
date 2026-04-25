"""Generic HTTP health detector for the flywheel framework.

Works for any service that exposes a /health endpoint returning 200
when healthy. Configured entirely via FlywheelConfig — no code changes
needed for different services.
"""

from __future__ import annotations

import time
from typing import Any

import requests
import structlog

from flywheel.detectors.base import Detector, DetectorResult, compute_signature_hash

logger = structlog.get_logger("flywheel.detectors.http")


class HTTPHealthDetector(Detector):
    """Generic HTTP health check detector.

    Polls a /health endpoint and checks:
    - HTTP status code is 200
    - Latency is below threshold (default 500ms)

    Works for any service — just configure base_url and thresholds.
    """

    name = "http_health"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        base_url: str = "http://localhost:8080",
        health_endpoint: str = "/health",
        latency_threshold_ms: float = 500,
    ) -> None:
        """Initialize HTTP health detector.

        Args:
            config: FlywheelConfig detector config
            base_url: Base URL of the service
            health_endpoint: Health check endpoint path
            latency_threshold_ms: Max acceptable latency in ms
        """
        super().__init__(config)
        self._base_url = base_url
        self._health_endpoint = health_endpoint
        self._latency_threshold_ms = latency_threshold_ms

    def detect(self) -> DetectorResult | None:
        """Poll the health endpoint and check for issues.

        Returns:
            DetectorResult if unhealthy or slow, None otherwise
        """
        url = f"{self._base_url}{self._health_endpoint}"
        start = time.monotonic()

        try:
            response = requests.get(url, timeout=5)
            latency_ms = (time.monotonic() - start) * 1000
        except requests.RequestException as e:
            logger.warning("Health check failed", url=url, error=str(e))
            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[health] Service unreachable at {url}",
                body=f"HTTP health check failed: {e}",
                labels=["health", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "http_health",
                    "unreachable",
                    {"url": url, "error": str(e)},
                ),
                severity="high",
                component="health",
            )

        # Check status code
        if response.status_code != 200:
            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[health] Service returned {response.status_code}",
                body=f"Health endpoint returned HTTP {response.status_code}\n\nResponse: {response.text[:500]}",
                labels=["health", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "http_health",
                    f"status_{response.status_code}",
                    {"url": url, "status": response.status_code},
                ),
                severity="high",
                component="health",
                metadata={"status_code": response.status_code, "latency_ms": latency_ms},
            )

        # Check latency
        if latency_ms > self._latency_threshold_ms:
            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[health] Latency {latency_ms:.0f}ms exceeds threshold",
                body=f"Health check latency {latency_ms:.0f}ms exceeds threshold of {self._latency_threshold_ms}ms",
                labels=["health", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "http_health",
                    "latency",
                    {"url": url, "latency_ms": int(latency_ms)},
                ),
                severity="medium",
                component="health",
                metadata={"latency_ms": latency_ms, "threshold_ms": self._latency_threshold_ms},
            )

        # Healthy
        return None