"""Base detector types for the flywheel framework.

Defines the Detector ABC and DetectorResult that all framework detectors
implement. Project-specific detectors inherit from these bases.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger("flywheel.detectors.base")


@dataclass
class IssueSignature:
    """Hashable signature for deduplicating issues.

    Used to detect when multiple detectors find the same underlying
    problem, so we don't create duplicate GitHub issues.
    """

    timestamp: str = ""
    component: str = ""
    signature_hash: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "component": self.component,
            "signature_hash": self.signature_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IssueSignature":
        return cls(
            timestamp=data.get("timestamp", ""),
            component=data.get("component", ""),
            signature_hash=data.get("signature_hash", ""),
        )


@dataclass
class DetectorResult:
    """Result of a detector run.

    Returned by Detector.detect(). Contains any issues found
    that should create GitHub issues.
    """

    name: str = ""
    is_issue: bool = False
    title: str = ""
    body: str = ""
    labels: list[str] = field(default_factory=list)
    signature: str = ""
    severity: str = "medium"
    component: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = "unknown"

    def build_signature(self) -> IssueSignature:
        """Build a hashable signature for deduplication."""
        return IssueSignature(
            component=self.component,
            signature_hash=self.signature,
        )


class Detector(ABC):
    """Abstract base class for all flywheel detectors.

    Detectors check for specific failure conditions and return
    DetectorResult when an issue is found. Framework runs all
    enabled detectors on each cycle.

    Subclasses must implement detect().
    """

    name: str = "unknown"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize detector with config.

        Args:
            config: Detector-specific config dict from FlywheelConfig
        """
        self._config = config or {}
        self._last_run_time: float = 0

    @abstractmethod
    def detect(self) -> DetectorResult | None:
        """Run detection check.

        Returns:
            DetectorResult if issue found, None otherwise
        """
        ...

    def should_run(self, interval: int) -> bool:
        """Check if enough time has passed since last run.

        Args:
            interval: Minimum seconds between runs

        Returns:
            True if detector should run now
        """
        import time

        now = time.time()
        if now - self._last_run_time < interval:
            return False
        self._last_run_time = now
        return True

    def threshold(self, key: str, default: Any = None) -> Any:
        """Get a threshold value from config.

        Args:
            key: Threshold key
            default: Default if not found

        Returns:
            Threshold value or default
        """
        return self._config.get(key, default)


def compute_signature_hash(component: str, issue_type: str, context: dict[str, Any]) -> str:
    """Compute a stable hash for issue deduplication.

    Args:
        component: The component name (e.g., "health", "wal", "logs")
        issue_type: The type of issue (e.g., "unhealthy", "oom")
        context: Additional context for the hash

    Returns:
        A SHA256 hash string truncated to 16 chars
    """
    stable_context = json.dumps(context, sort_keys=True, default=str)
    raw = f"{component}:{issue_type}:{stable_context}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]