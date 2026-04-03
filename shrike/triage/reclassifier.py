"""Reclassification for low-relevance events.

When an event scores below 0.3, it may be misclassified — the wrong OCSF class
was assigned, making the event appear irrelevant when it might carry security value
under the correct class.

The reclassifier runs pattern extraction without class constraints (class_uid=0)
to see if a different class fits better.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shrike.evaluate.types import get_nested


# Security-relevant fields by class. If we find 5+ of these populated
# for a different class than the current one, suggest reclassification.
CLASS_FIELD_SIGNATURES: dict[int, list[str]] = {
    3002: [  # Authentication
        "user.name", "src_endpoint.ip", "status", "auth_protocol",
        "dst_endpoint.ip", "actor.user.name", "session.uid",
        "status_id", "activity_id",
    ],
    3001: [  # Account Lifecycle
        "user.name", "activity_name", "actor.user.name",
        "user.uid", "user.type", "status",
    ],
    1007: [  # Process Activity
        "process.name", "process.cmd_line", "process.pid",
        "process.parent_process.name", "process.file.path",
        "actor.user.name", "device.hostname",
    ],
    4001: [  # Network Activity
        "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port",
        "connection_info.protocol_name", "traffic.bytes_in",
        "traffic.bytes_out", "connection_info.direction",
    ],
    4003: [  # DNS Activity
        "query.hostname", "query.type", "src_endpoint.ip",
        "answers", "dst_endpoint.ip", "status",
    ],
    4002: [  # HTTP Activity
        "http_request.url.path", "http_request.http_method",
        "src_endpoint.ip", "dst_endpoint.ip",
        "http_response.code", "user_agent",
    ],
    2004: [  # Vulnerability Finding
        "finding_info.title", "finding_info.uid", "severity_id",
        "src_endpoint.ip", "dst_endpoint.ip", "status",
    ],
    6003: [  # API Activity
        "api.operation", "api.service.name", "actor.user.name",
        "src_endpoint.ip", "http_request.http_method", "status",
    ],
    1006: [  # Scheduled Job Activity
        "process.cmd_line", "user.name", "process.pid",
        "activity_name", "device.hostname",
    ],
}

MIN_FIELD_MATCH_THRESHOLD = 5


@dataclass
class ReclassificationResult:
    """Result of a reclassification attempt."""
    should_reclassify: bool
    original_class: int
    suggested_class: int
    suggested_class_name: str
    confidence: float               # 0.0 - 1.0
    evidence: dict[str, Any]        # fields matched, scores, etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "should_reclassify": self.should_reclassify,
            "original_class": self.original_class,
            "suggested_class": self.suggested_class,
            "suggested_class_name": self.suggested_class_name,
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence,
        }


# Class UID → human-readable name
CLASS_NAMES: dict[int, str] = {
    3002: "Authentication",
    3001: "Account Lifecycle",
    3003: "Authorization",
    1007: "Process Activity",
    4001: "Network Activity",
    4003: "DNS Activity",
    4002: "HTTP Activity",
    2004: "Vulnerability Finding",
    6003: "API Activity",
    1001: "System Activity",
    1006: "Scheduled Job Activity",
    3004: "Group Management",
    3005: "User Access Management",
    1008: "File Activity",
    4007: "Network Session",
    4009: "Email Activity",
    6002: "Application Lifecycle",
}


class Reclassifier:
    """Attempts reclassification for low-relevance events.

    Args:
        relevance_threshold: Events below this score trigger reclassification.
            Default: 0.3
        min_field_matches: Minimum number of fields matching a different class
            to suggest reclassification. Default: 5
    """

    def __init__(
        self,
        relevance_threshold: float = 0.3,
        min_field_matches: int = MIN_FIELD_MATCH_THRESHOLD,
    ):
        self._threshold = relevance_threshold
        self._min_fields = min_field_matches

    def should_attempt(self, relevance_score: float) -> bool:
        """Check whether reclassification should be attempted."""
        return relevance_score < self._threshold

    def reclassify(self, event: dict[str, Any]) -> ReclassificationResult:
        """Attempt to find a better OCSF class for the event.

        Scans the event's populated fields against class field signatures.
        If a different class matches with enough fields, suggests reclassification.

        Args:
            event: OCSF-normalized event dict with current (possibly wrong) class.

        Returns:
            ReclassificationResult with recommendation.
        """
        original_class = event.get("class_uid", 0)

        # Score each candidate class by field signature match
        candidates: list[tuple[int, int, list[str]]] = []

        for class_uid, signature_fields in CLASS_FIELD_SIGNATURES.items():
            if class_uid == original_class:
                continue

            matched_fields = []
            for field_path in signature_fields:
                val = get_nested(event, field_path)
                if val is not None and str(val) not in ("", "None", "unknown", "0"):
                    matched_fields.append(field_path)

            if len(matched_fields) >= self._min_fields:
                candidates.append((class_uid, len(matched_fields), matched_fields))

        if not candidates:
            return ReclassificationResult(
                should_reclassify=False,
                original_class=original_class,
                suggested_class=original_class,
                suggested_class_name=CLASS_NAMES.get(original_class, f"Unknown ({original_class})"),
                confidence=0.0,
                evidence={"reason": "no alternative class matched enough fields"},
            )

        # Pick best candidate (most field matches)
        candidates.sort(key=lambda x: -x[1])
        best_class, best_count, best_fields = candidates[0]

        # Confidence: field match ratio against the target class signature
        total_signature_fields = len(CLASS_FIELD_SIGNATURES[best_class])
        confidence = best_count / total_signature_fields

        return ReclassificationResult(
            should_reclassify=True,
            original_class=original_class,
            suggested_class=best_class,
            suggested_class_name=CLASS_NAMES.get(best_class, f"Unknown ({best_class})"),
            confidence=confidence,
            evidence={
                "matched_fields": best_fields,
                "match_count": best_count,
                "signature_size": total_signature_fields,
                "other_candidates": [
                    {
                        "class_uid": c[0],
                        "class_name": CLASS_NAMES.get(c[0], f"Unknown ({c[0]})"),
                        "match_count": c[1],
                    }
                    for c in candidates[1:3]  # Show up to 2 runners-up
                ],
            },
        )
