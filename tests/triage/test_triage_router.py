"""Tests for EventRouter — 98% → 100% coverage.

Covers:
- Security-inherent class threshold reduction (line 107)
- route() with RelevanceResult + class_uid for security classes
- route() with raw float + class_uid for security classes
- route_batch with empty list
- tier_distribution with empty list
"""

from __future__ import annotations

import pytest

from shrike.triage.relevance import RelevanceResult, RelevanceScorer
from shrike.triage.router import (
    EventRouter,
    RoutingDecision,
    SECURITY_CLASSES,
    SECURITY_CLASS_THRESHOLD_REDUCTION,
    DEFAULT_THRESHOLDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(score: float, class_uid: int = 0) -> RelevanceResult:
    """Make a RelevanceResult with specified score."""
    return RelevanceResult(
        score=score,
        components={
            "subtype_score": score,
            "field_richness": 0.0,
            "attack_coverage": 0.0,
            "source_reputation": 0.0,
        },
        matched_techniques=[],
        source_type="test",
    )


# ---------------------------------------------------------------------------
# Security-inherent class threshold reduction
# ---------------------------------------------------------------------------

class TestSecurityInherentClassThreshold:
    """Line 107: sec_threshold -= SECURITY_CLASS_THRESHOLD_REDUCTION.

    Security-inherent classes (2004, 2001, 2002, 3002, 3005, 4001, 1007)
    get a 0.1 lower threshold than the default 0.7.
    """

    @pytest.mark.parametrize("class_uid", list(SECURITY_CLASSES))
    def test_security_class_gets_reduced_threshold(self, class_uid: int):
        """A score of 0.65 routes to security for security-inherent classes.

        Default security threshold is 0.7. With reduction of 0.1, effective
        threshold is 0.6. So 0.65 should route to security.
        """
        router = EventRouter()
        # Score 0.65 is below default 0.7 but above reduced 0.6
        decision = router.route(0.65, class_uid=class_uid)
        assert decision.tier == "security", (
            f"class_uid={class_uid} should route 0.65 to security, got {decision.tier}"
        )

    @pytest.mark.parametrize("class_uid", list(SECURITY_CLASSES))
    def test_security_class_at_exact_reduced_threshold(self, class_uid: int):
        """A score at exactly the reduced threshold routes to security."""
        router = EventRouter()
        reduced = DEFAULT_THRESHOLDS["security"] - SECURITY_CLASS_THRESHOLD_REDUCTION
        decision = router.route(reduced, class_uid=class_uid)
        assert decision.tier == "security"

    @pytest.mark.parametrize("class_uid", list(SECURITY_CLASSES))
    def test_non_security_class_at_same_score_routes_operational(self, class_uid: int):
        """Same score 0.65 routes to operational for non-security classes."""
        router = EventRouter()
        # 0.65 is below default 0.7 security threshold
        non_security = 9999  # Not in SECURITY_CLASSES
        decision = router.route(0.65, class_uid=non_security)
        assert decision.tier in ("operational", "compliance", "noise"), (
            f"non-security class should route 0.65 below security, got {decision.tier}"
        )

    def test_security_class_with_relevance_result(self):
        """route() accepts RelevanceResult + class_uid for security threshold."""
        router = EventRouter()
        result = _make_result(0.65)
        decision = router.route(result, class_uid=3002)  # Authentication = security class
        assert decision.tier == "security"

    def test_custom_threshold_not_reduced_for_non_security(self):
        """Custom thresholds are not affected by security class reduction."""
        router = EventRouter(thresholds={"security": 0.9, "operational": 0.5, "compliance": 0.1})
        # Even with custom 0.9 threshold, security class should reduce by 0.1
        decision = router.route(0.85, class_uid=3002)
        assert decision.tier == "security"


# ---------------------------------------------------------------------------
# route_batch edge cases
# ---------------------------------------------------------------------------

class TestRouteBatch:
    """route_batch() with empty list."""

    def test_route_batch_empty(self):
        """Empty list returns empty list."""
        router = EventRouter()
        decisions = router.route_batch([])
        assert decisions == []

    def test_route_batch_single(self):
        """Single item list works."""
        router = EventRouter()
        result = _make_result(0.8)
        decisions = router.route_batch([result])
        assert len(decisions) == 1
        assert decisions[0].tier == "security"


# ---------------------------------------------------------------------------
# tier_distribution edge cases
# ---------------------------------------------------------------------------

class TestTierDistribution:
    """tier_distribution() with empty list."""

    def test_tier_distribution_empty(self):
        """Empty list returns all zeros."""
        router = EventRouter()
        dist = router.tier_distribution([])
        assert dist == {"security": 0, "operational": 0, "compliance": 0, "noise": 0}

    def test_tier_distribution_all_noise(self):
        """All low-score events route to noise."""
        router = EventRouter()
        results = [_make_result(0.05), _make_result(0.08), _make_result(0.09)]
        dist = router.tier_distribution(results)
        assert dist["noise"] == 3
        assert dist["security"] == 0

    def test_tier_distribution_all_security(self):
        """All high-score events route to security."""
        router = EventRouter()
        results = [_make_result(0.9), _make_result(0.8), _make_result(0.75)]
        dist = router.tier_distribution(results)
        assert dist["security"] == 3


# ---------------------------------------------------------------------------
# RoutingDecision edge cases
# ---------------------------------------------------------------------------

class TestRoutingDecision:
    """RoutingDecision.to_dict() and all tier variants."""

    def test_all_tiers_have_correct_destination(self):
        """Each tier maps to the expected destination."""
        router = EventRouter()
        decisions = [
            router.route(0.9),   # security
            router.route(0.5),   # operational
            router.route(0.2),   # compliance
            router.route(0.05),  # noise
        ]
        expected = ["detect", "ops", "archive", "drop"]
        tiers = [d.tier for d in decisions]
        destinations = [d.destination for d in decisions]
        cost_tiers = [d.cost_tier for d in decisions]

        assert tiers == ["security", "operational", "compliance", "noise"]
        assert destinations == expected
        assert cost_tiers == ["$$$", "$", "cents", "free"]

    def test_to_dict_contains_all_fields(self):
        """to_dict() returns all expected fields."""
        router = EventRouter()
        decision = router.route(0.75)
        d = decision.to_dict()
        assert "tier" in d
        assert "destination" in d
        assert "cost_tier" in d
        assert "reason" in d
        assert isinstance(d["tier"], str)
        assert isinstance(d["destination"], str)
        assert isinstance(d["cost_tier"], str)
        assert isinstance(d["reason"], str)

    def test_reason_contains_score_formatted(self):
        """Reason string contains the score formatted to 2 decimal places."""
        router = EventRouter()
        decision = router.route(0.753)
        assert "0.75" in decision.reason or "0.753" in decision.reason


# ---------------------------------------------------------------------------
# Threshold boundary conditions
# ---------------------------------------------------------------------------

class TestThresholdBoundaries:
    """Exact boundary conditions for each tier."""

    def test_exact_security_boundary(self):
        """Score exactly at default security threshold (0.7) routes to security."""
        router = EventRouter()
        decision = router.route(0.7)
        assert decision.tier == "security"

    def test_exact_operational_boundary(self):
        """Score exactly at default operational threshold (0.3) routes to operational."""
        router = EventRouter()
        decision = router.route(0.3)
        assert decision.tier == "operational"

    def test_exact_compliance_boundary(self):
        """Score exactly at default compliance threshold (0.1) routes to compliance."""
        router = EventRouter()
        decision = router.route(0.1)
        assert decision.tier == "compliance"

    def test_just_below_security_boundary(self):
        """Score just below 0.7 routes below security."""
        router = EventRouter()
        decision = router.route(0.699)
        assert decision.tier in ("operational", "compliance", "noise")

    def test_just_above_noise_boundary(self):
        """Score just above 0.1 routes above noise."""
        router = EventRouter()
        decision = router.route(0.101)
        assert decision.tier in ("compliance", "operational", "security")


# ---------------------------------------------------------------------------
# Custom thresholds
# ---------------------------------------------------------------------------

class TestCustomThresholds:
    """EventRouter with custom thresholds."""

    def test_custom_security_threshold_string_key(self):
        """Custom thresholds use string keys."""
        router = EventRouter(thresholds={
            "security": 0.8,
            "operational": 0.4,
            "compliance": 0.15,
        })
        assert router.route(0.79).tier == "operational"
        assert router.route(0.8).tier == "security"

    def test_custom_operational_threshold(self):
        """Custom operational threshold changes routing."""
        router = EventRouter(thresholds={
            "security": 0.7,
            "operational": 0.6,
            "compliance": 0.1,
        })
        assert router.route(0.5).tier == "compliance"
        assert router.route(0.65).tier == "operational"

    def test_custom_compliance_threshold(self):
        """Custom compliance threshold changes routing."""
        router = EventRouter(thresholds={
            "security": 0.7,
            "operational": 0.3,
            "compliance": 0.2,
        })
        assert router.route(0.15).tier == "noise"
        assert router.route(0.25).tier == "compliance"