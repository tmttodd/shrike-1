"""Event routing based on relevance scores.

Maps relevance scores to routing tiers with cost model awareness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shrike.triage.relevance import RelevanceResult


@dataclass
class RoutingDecision:
    """Routing decision for a single event."""
    tier: str               # "security", "operational", "compliance", "noise"
    destination: str        # hint: "detect", "ops", "archive", "drop"
    cost_tier: str          # "$$$", "$", "cents", "free"
    reason: str             # Human-readable explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "destination": self.destination,
            "cost_tier": self.cost_tier,
            "reason": self.reason,
        }


# Default tier boundaries
DEFAULT_THRESHOLDS = {
    "security": 0.7,       # >= 0.7 → security (hot path)
    "operational": 0.3,    # >= 0.3 → operational (warm path)
    "compliance": 0.1,     # >= 0.1 → compliance (cold archive)
    # < 0.1 → noise (drop)
}

# Security-inherent OCSF classes get a lower threshold
# These classes are always security-relevant — even with sparse fields
SECURITY_CLASSES = {
    2004,  # Detection Finding
    2001,  # Security Finding
    2002,  # Vulnerability Finding
    3002,  # Authentication
    3005,  # User Access Management
    4001,  # Network Activity (when it has IPS/IDS context)
    1007,  # Process Activity (when it has cmd_line)
}

# Threshold reduction for security-inherent classes
SECURITY_CLASS_THRESHOLD_REDUCTION = 0.1  # 0.7 → 0.6 for security classes


TIER_CONFIG = {
    "security": {
        "destination": "detect",
        "cost_tier": "$$$",
        "reason_template": "High relevance ({score:.2f}) — security hot path",
    },
    "operational": {
        "destination": "ops",
        "cost_tier": "$",
        "reason_template": "Moderate relevance ({score:.2f}) — operational warm path",
    },
    "compliance": {
        "destination": "archive",
        "cost_tier": "cents",
        "reason_template": "Low relevance ({score:.2f}) — compliance cold archive",
    },
    "noise": {
        "destination": "drop",
        "cost_tier": "free",
        "reason_template": "Minimal relevance ({score:.2f}) — noise, drop or sample",
    },
}


class EventRouter:
    """Routes events based on relevance scores.

    Args:
        thresholds: Optional override for tier boundaries.
            Keys: "security", "operational", "compliance".
            Values: minimum score for that tier (float).
    """

    def __init__(self, thresholds: dict[str, float] | None = None):
        self._thresholds = thresholds or dict(DEFAULT_THRESHOLDS)

    def route(self, relevance: RelevanceResult | float,
              class_uid: int = 0) -> RoutingDecision:
        """Route an event based on its relevance score.

        Args:
            relevance: Either a RelevanceResult or a raw float score (0.0-1.0).
            class_uid: OCSF class UID — security-inherent classes get a lower threshold.

        Returns:
            RoutingDecision with tier, destination, cost tier, and reason.
        """
        score = relevance.score if isinstance(relevance, RelevanceResult) else relevance

        # Security-inherent classes get a lower threshold
        sec_threshold = self._thresholds["security"]
        if class_uid in SECURITY_CLASSES:
            sec_threshold -= SECURITY_CLASS_THRESHOLD_REDUCTION

        if score >= sec_threshold:
            tier = "security"
        elif score >= self._thresholds["operational"]:
            tier = "operational"
        elif score >= self._thresholds["compliance"]:
            tier = "compliance"
        else:
            tier = "noise"

        config = TIER_CONFIG[tier]
        return RoutingDecision(
            tier=tier,
            destination=config["destination"],
            cost_tier=config["cost_tier"],
            reason=config["reason_template"].format(score=score),
        )

    def route_batch(
        self, results: list[RelevanceResult]
    ) -> list[RoutingDecision]:
        """Route a batch of events."""
        return [self.route(r) for r in results]

    def tier_distribution(
        self, results: list[RelevanceResult]
    ) -> dict[str, int]:
        """Count events per tier for a batch."""
        counts: dict[str, int] = {"security": 0, "operational": 0, "compliance": 0, "noise": 0}
        for r in results:
            decision = self.route(r)
            counts[decision.tier] += 1
        return counts
