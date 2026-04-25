"""Splunk metric detector for Shrike.

Queries Splunk for Shrike-related error events.
Shrike-specific — not reusable without modification.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

import requests
import structlog

from flywheel.detectors.base import Detector, DetectorResult, compute_signature_hash

logger = structlog.get_logger("shrike_flywheel.detectors.splunk")


class SplunkDetector(Detector):
    """Splunk-based detector for Shrike.

    Queries Splunk for:
    - Classification error rate (>5% = issue)
    - Extraction quality events
    """

    name = "splunk"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        splunk_url: str | None = None,
        splunk_token: str | None = None,
        error_rate_threshold: float = 0.05,
        window_minutes: int = 10,
    ) -> None:
        """Initialize Splunk detector.

        Args:
            config: FlywheelConfig detector config
            splunk_url: Splunk HEC URL
            splunk_token: Splunk HEC token
            error_rate_threshold: Max error rate before issue
            window_minutes: Time window to analyze
        """
        super().__init__(config)
        self._splunk_url = splunk_url or os.getenv("SPLUNK_HEC_URL", "")
        self._splunk_token = splunk_token or os.getenv("SPLUNK_HEC_TOKEN", "")
        self._error_rate_threshold = error_rate_threshold
        self._window_seconds = window_minutes * 60

    def detect(self) -> DetectorResult | None:
        """Query Splunk for error metrics.

        Returns:
            DetectorResult if threshold exceeded, None otherwise
        """
        if not self.should_run(60):
            return None

        if not self._splunk_url:
            logger.debug("Splunk URL not configured, skipping")
            return None

        # Check classification error rate
        result = self._check_classification_errors()
        if result:
            return result

        return None

    def _check_classification_errors(self) -> Optional[DetectorResult]:
        """Query Splunk for classification error rate."""
        try:
            # Build Splunk search
            earliest = f"-{self._window_seconds}s"
            search_query = (
                'search index="ocsf-*" sourcetype="shrike" '
                '| eval has_error=if(isnotnull(error) OR status="failed", 1, 0) '
                f"| stats count AS total, sum(has_error) AS errors "
                f"| eval error_rate=errors/total "
                f"| where error_rate > {self._error_rate_threshold}"
            )

            splunk_url = self._splunk_url.replace(":8088", ":8089")
            auth = (self._splunk_token, "")
            params = {
                "search": search_query,
                "earliest_time": earliest,
                "latest_time": "now",
                "output_mode": "json",
            }

            response = requests.get(
                f"{splunk_url}/services/search/jobs",
                auth=auth,
                params=params,
                timeout=30,
            )

            if response.status_code != 200:
                logger.warning("Splunk search failed", status=response.status_code)
                return None

            results = response.json()
            if not results.get("results"):
                return None

            error_rate = float(results["results"][0].get("error_rate", 0))

            return DetectorResult(
                name=self.name,
                is_issue=True,
                title=f"[splunk] Classification error rate {error_rate:.1%} exceeds threshold",
                body=f"Classification error rate {error_rate:.1%} exceeds threshold of {self._error_rate_threshold:.1%}",
                labels=["splunk", "flywheel-candidate"],
                signature=compute_signature_hash(
                    "splunk",
                    "classification_error",
                    {
                        "error_rate": error_rate,
                        "threshold": self._error_rate_threshold,
                    },
                ),
                severity="medium",
                component="classifier",
                metadata={
                    "error_rate": error_rate,
                    "threshold": self._error_rate_threshold,
                },
            )

        except Exception as e:
            logger.warning("Failed to query Splunk", error=str(e))
            return None