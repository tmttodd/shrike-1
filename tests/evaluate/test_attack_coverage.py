"""Tests for attack_coverage module — ATT&CK technique detection coverage."""

from __future__ import annotations

import pytest

from shrike.evaluate.attack_coverage import (
    ATTACK_TECHNIQUE_MAP,
    measure_attack_coverage,
)
from shrike.evaluate.types import DimensionScore
from shrike.extractor.schema_injected_extractor import ExtractionResult


class TestMeasureAttackCoverage:
    """Tests for measure_attack_coverage function."""

    def test_no_results_returns_zero(self):
        """No extraction results returns zero score."""
        result = measure_attack_coverage([])
        assert result.score == 0.0
        assert result.total == 0

    def test_no_class_events_all_blind(self):
        """No events in required OCSF classes = all blind."""
        # Empty extraction result (no class match)
        results = [
            (None, {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        assert result.score == 0.0
        assert result.metadata["blind"] > 0

    def test_single_event_covered(self):
        """T1078 (Valid Accounts) covered when auth events have required fields."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
        }
        results = [
            (ExtractionResult(event=event, method="pattern", confidence=0.9), {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        # T1078 should be covered
        assert "T1078" in result.metadata["techniques"]
        assert result.metadata["techniques"]["T1078"]["status"] == "covered"

    def test_missing_required_fields_partial(self):
        """Missing required fields = partial coverage."""
        # Event missing src_endpoint.ip
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "status": "success",
        }
        results = [
            (ExtractionResult(event=event, method="pattern", confidence=0.9), {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        assert "T1078" in result.metadata["techniques"]
        assert result.metadata["techniques"]["T1078"]["status"] in ("partial", "blind")

    def test_activity_filter_respected(self):
        """Activity filter only counts matching activity_id events."""
        # T1078 only wants activity_id=1 (Logon)
        event_logon = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
        }
        event_logoff = {
            "class_uid": 3002,
            "activity_id": 2,  # Logoff — not in activity_filter
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
        }
        results = [
            (ExtractionResult(event=event_logon, method="pattern", confidence=0.9), {"class_uid": 3002}),
            (ExtractionResult(event=event_logoff, method="pattern", confidence=0.9), {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        # T1078 should still be covered (activity filter uses best match)
        assert "T1078" in result.metadata["techniques"]

    def test_nice_to_have_bonus(self):
        """Nice-to-have fields provide up to 20% bonus."""
        # Event with all required + nice_to_have fields
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
            "auth_protocol": "SSH",
            "actor": {"user": {"name": "alice"}},
        }
        results = [
            (ExtractionResult(event=event, method="pattern", confidence=0.9), {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        assert "T1078" in result.metadata["techniques"]
        tech = result.metadata["techniques"]["T1078"]
        assert tech["status"] == "covered"
        assert tech["confidence"] >= 0.7

    def test_multiple_techniques_scored(self):
        """Multiple techniques scored independently."""
        # T1078 (Valid Accounts) + T1059 (Command and Scripting Interpreter)
        auth_event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
        }
        process_event = {
            "class_uid": 1007,
            "activity_id": 1,
            "process": {"name": "bash", "cmd_line": "ls -la"},
        }
        results = [
            (ExtractionResult(event=auth_event, method="pattern", confidence=0.9), {"class_uid": 3002}),
            (ExtractionResult(event=process_event, method="pattern", confidence=0.9), {"class_uid": 1007}),
        ]
        result = measure_attack_coverage(results)
        assert "T1078" in result.metadata["techniques"]
        assert "T1059" in result.metadata["techniques"]
        # Both should be covered
        assert result.metadata["covered"] >= 2

    def test_subscores_by_detection_type(self):
        """Sub-scores computed for single_event, behavioral, enriched."""
        event = {
            "class_uid": 3002,
            "activity_id": 1,
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1"},
            "status": "success",
        }
        results = [
            (ExtractionResult(event=event, method="pattern", confidence=0.9), {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        assert "normalization_coverage_pct" in result.metadata
        assert "detection_readiness_pct" in result.metadata
        assert "single_event_techniques" in result.metadata
        assert "behavioral_techniques" in result.metadata

    def test_tactic_gaps_grouped(self):
        """Blind techniques grouped by tactic in failures."""
        # Only empty results = all blind
        results = [
            (None, {"class_uid": 3002}),
        ]
        result = measure_attack_coverage(results)
        # Should have failures grouped by tactic
        assert len(result.failures) > 0
        assert result.failures[0].category == "tactic_gap"

    def test_technique_map_complete(self):
        """ATTACK_TECHNIQUE_MAP has all expected techniques."""
        assert "T1078" in ATTACK_TECHNIQUE_MAP  # Valid Accounts
        assert "T1059" in ATTACK_TECHNIQUE_MAP  # Command and Scripting Interpreter
        assert "T1110" in ATTACK_TECHNIQUE_MAP  # Brute Force
        assert "T1571" in ATTACK_TECHNIQUE_MAP  # Non-Standard Port
        # All have required structure
        for tech_id, tech in ATTACK_TECHNIQUE_MAP.items():
            assert "name" in tech
            assert "tactic" in tech
            assert "detection_type" in tech
            assert "ocsf_classes" in tech
            assert len(tech["ocsf_classes"]) > 0

    def test_all_required_fields_collected(self):
        """_ALL_REQUIRED_FIELDS collected from all techniques."""
        from shrike.evaluate.attack_coverage import _ALL_REQUIRED_FIELDS
        assert len(_ALL_REQUIRED_FIELDS) > 0
        # Common fields should be present
        assert "user" in _ALL_REQUIRED_FIELDS
        assert "src_endpoint.ip" in _ALL_REQUIRED_FIELDS