"""shrike.triage — Event-level relevance scoring and routing.

Scores each OCSF event on a 0.0-1.0 relevance scale and routes it to the
appropriate tier: security (hot), operational (warm), compliance (cold), or noise (drop).

Usage:
    from shrike.triage import RelevanceScorer, EventRouter

    scorer = RelevanceScorer()
    router = EventRouter()

    result = scorer.score(event)
    route = router.route(result)
"""

from shrike.triage.relevance import RelevanceScorer, RelevanceResult
from shrike.triage.router import EventRouter, RoutingDecision
from shrike.triage.reclassifier import Reclassifier, ReclassificationResult

__all__ = [
    "RelevanceScorer",
    "RelevanceResult",
    "EventRouter",
    "RoutingDecision",
    "Reclassifier",
    "ReclassificationResult",
]
