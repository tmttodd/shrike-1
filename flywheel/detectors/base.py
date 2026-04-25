"""Base detector types for the flywheel system."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class IssueSignature:
    """Hashable signature for deduplicating issues."""

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
class Detection:
    """Base class for a single detection result."""

    detected_at: str = ""

    def __post_init__(self) -> None:
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat() + "Z"


@dataclass
class DetectorResult:
    """Result of a detector run."""

    detections: list[Any] = field(default_factory=list)
    issues: list[Any] = field(default_factory=list)


def compute_signature_hash(component: str, issue_type: str, context: dict[str, Any]) -> str:
    """Compute a stable hash for issue deduplication.

    Args:
        component: The component name (e.g., "health", "wal", "logs")
        issue_type: The type of issue (e.g., "unhealthy", "oom", "extraction_error")
        context: Additional context for the hash (e.g., error message, stack trace)

    Returns:
        A SHA256 hash string for deduplication.
    """
    # Sort keys for stable serialization
    stable_context = json.dumps(context, sort_keys=True, default=str)
    raw = f"{component}:{issue_type}:{stable_context}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]