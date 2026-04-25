"""Splunk detector — queries Splunk for Shrike-related error events."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog

from flywheel.detectors.base import Detection, DetectorResult, IssueSignature, compute_signature_hash

logger = structlog.get_logger("flywheel.detector.splunk")

# Threshold: >5% classification error rate = issue
CLASSIFICATION_ERROR_RATE_THRESHOLD = 0.05
WINDOW_SECONDS = 600


@dataclass
class SplunkIssueSignature(IssueSignature):
    """Signature for Splunk-detected issues."""

    issue_type: str = ""  # "high_classification_error", "low_extraction_quality"
    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0


@dataclass
class SplunkDetection(Detection):
    """A single Splunk-based detection."""

    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0
    sample_events: list[dict[str, Any]] = field(default_factory=list)


class SplunkDetector:
    """Detect issues by querying Splunk for Shrike-related events.

    Searches Splunk for:
    - "shrike" in logs with error categories
    - High classification error rate (>5% = issue)
    - Low extraction quality events
    """

    name = "splunk"

    def __init__(
        self,
        splunk_hec_url: Optional[str] = None,
        splunk_hec_token: Optional[str] = None,
        error_rate_threshold: float = CLASSIFICATION_ERROR_RATE_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ) -> None:
        self._splunk_hec_url = splunk_hec_url or os.getenv("SPLUNK_HEC_URL", "")
        self._splunk_hec_token = splunk_hec_token or os.getenv("SPLUNK_HEC_TOKEN", "")
        self._error_rate_threshold = error_rate_threshold
        self._window_seconds = window_seconds
        self._last_check_time: float = 0

    def detect(self) -> DetectorResult:
        """Run a single detection cycle. Returns issues found."""
        now = time.time()
        if now - self._last_check_time < 60:  # Minimum 60s between checks
            return DetectorResult(detections=[], issues=[])

        self._last_check_time = now
        detections: list[SplunkDetection] = []
        issues: list[SplunkDetection] = []

        if not self._splunk_hec_url:
            logger.debug("Splunk HEC URL not configured, skipping")
            return DetectorResult(detections=[], issues=[])

        # Check classification error rate
        classification_detection = self._check_classification_errors()
        if classification_detection:
            detections.append(classification_detection)
            if classification_detection.metric_value > classification_detection.threshold:
                issues.append(classification_detection)

        # Check extraction quality
        quality_detection = self._check_extraction_quality()
        if quality_detection:
            detections.append(quality_detection)
            if quality_detection.metric_value < 0.5:  # <50% quality = issue
                issues.append(quality_detection)

        return DetectorResult(detections=detections, issues=issues)

    def _check_classification_errors(self) -> Optional[SplunkDetection]:
        """Query Splunk for classification error rate."""
        try:
            # Build Splunk search query
            earliest = f"-{self._window_seconds}s"
            search_query = (
                'search index="ocsf-*" sourcetype="shrike" '
                '| eval has_error=if(isnotnull(error) OR status="failed", 1, 0) '
                f"| stats count AS total, sum(has_error) AS errors BY source "
                f"| eval error_rate=errors/total "
                f"| where error_rate > {self._error_rate_threshold}"
            )

            # Use Splunk REST API to search
            import requests

            splunk_url = self._splunk_hec_url.replace(":8088", ":8089")
            if not splunk_url:
                return None

            auth = (self._splunk_hec_token, "")
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

            sample_events = results.get("results", [])[:5]
            error_rate = float(results["results"][0].get("error_rate", 0))

            return SplunkDetection(
                metric_name="classification_error_rate",
                metric_value=error_rate,
                threshold=self._error_rate_threshold,
                sample_events=sample_events,
            )
        except Exception as e:
            logger.warning("Failed to query Splunk", error=str(e))
            return None

    def _check_extraction_quality(self) -> Optional[SplunkDetection]:
        """Query Splunk for extraction quality metrics."""
        try:
            earliest = f"-{self._window_seconds}s"
            search_query = (
                'search index="ocsf-*" sourcetype="shrike" '
                "| eval has_fields=if(field_count >= 3, 1, 0) "
                "| stats count AS total, sum(has_fields) AS good "
                "| eval quality_rate=good/total"
            )

            import requests

            splunk_url = self._splunk_hec_url.replace(":8088", ":8089")
            if not splunk_url:
                return None

            auth = (self._splunk_hec_token, "")
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
                return None

            results = response.json()
            if not results.get("results"):
                return None

            sample_events = results.get("results", [])[:5]
            quality_rate = float(results["results"][0].get("quality_rate", 1.0))

            return SplunkDetection(
                metric_name="extraction_quality_rate",
                metric_value=quality_rate,
                threshold=0.5,
                sample_events=sample_events,
            )
        except Exception as e:
            logger.warning("Failed to query Splunk for quality", error=str(e))
            return None

    def build_signature(self, detection: SplunkDetection) -> SplunkIssueSignature:
        """Build an issue signature from a Splunk detection."""
        context = {
            "metric_name": detection.metric_name,
            "metric_value": detection.metric_value,
            "threshold": detection.threshold,
        }

        return SplunkIssueSignature(
            issue_type="splunk_metric",
            metric_name=detection.metric_name,
            metric_value=detection.metric_value,
            threshold=detection.threshold,
            signature_hash=compute_signature_hash(
                "splunk", detection.metric_name, context
            ),
        )