"""Tests for Sigma rule engine."""

import pytest
import tempfile
import os
from pathlib import Path

from shrike.detect.sigma.rule_engine import SigmaRuleEngine
from shrike.detect.sigma.rule_loader import SigmaRuleLoader
from shrike.detect.sigma.ocsf_mapper import OCSFFieldMapper
from shrike.detect.patterns.sequence_matcher import SequenceMatcher


class TestOCSFFieldMapper:
    """Tests for OCSF field mapping."""

    def test_windows_field_mapping(self):
        mapper = OCSFFieldMapper()
        assert mapper.map_field("Image") == "process.file.path"
        assert mapper.map_field("CommandLine") == "process.cmd_line"
        assert mapper.map_field("ParentImage") == "process.parent_process.file.path"

    def test_generic_field_mapping(self):
        mapper = OCSFFieldMapper()
        assert mapper.map_field("user") == "user.name"
        assert mapper.map_field("src_ip") == "src_endpoint.ip"
        assert mapper.map_field("dst_port") == "dst_endpoint.port"

    def test_unknown_field(self):
        mapper = OCSFFieldMapper()
        assert mapper.map_field("unknown_field_xyz") is None

    def test_class_uid_mapping(self):
        mapper = OCSFFieldMapper()
        assert mapper.get_class_uid_for_logsource("process_creation") == 1007
        assert mapper.get_class_uid_for_logsource("authentication") == 3002
        assert mapper.get_class_uid_for_logsource("network_connection") == 4001


class TestWildcardToRegex:
    """Tests for wildcard pattern matching."""

    def test_exact_match(self):
        engine = SigmaRuleEngine()
        # Access private method for testing
        assert engine._values_match("powershell.exe", "powershell.exe")

    def test_wildcard_suffix(self):
        engine = SigmaRuleEngine()
        assert engine._values_match("powershell.exe", "powershell*")
        assert engine._values_match("pwsh.exe", "powershell*") is False

    def test_wildcard_prefix(self):
        engine = SigmaRuleEngine()
        assert engine._values_match("system32", "*32")

    def test_wildcard_both(self):
        engine = SigmaRuleEngine()
        assert engine._values_match("abc", "*abc*")
        assert engine._values_match("xyzabc123", "*abc*")

    def test_question_mark(self):
        engine = SigmaRuleEngine()
        assert engine._values_match("abc", "???")
        assert engine._values_match("abcd", "???") is False


class TestSigmaRuleLoader:
    """Tests for Sigma rule loading."""

    def test_parse_basic_rule(self):
        loader = SigmaRuleLoader()
        raw_rule = {
            "title": "Test Rule",
            "status": "experimental",
            "level": "high",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"Image": "*\\malware.exe"},
                "condition": "selection"
            },
            "tags": ["attack.t1204"]
        }

        rule = loader._parse_rule(raw_rule, "test.yaml")
        assert rule["title"] == "Test Rule"
        assert rule["status"] == "experimental"
        assert rule["level"] == "high"
        assert "T1204" in rule["mitre_techniques"]

    def test_extract_mitre_techniques(self):
        loader = SigmaRuleLoader()
        tags = ["attack.t1110.001", "attack.t1078", "attack.credential_access"]
        techniques = loader._extract_mitre_techniques(tags)
        assert "T1110.001" in techniques
        assert "T1078" in techniques


class TestSequenceMatcher:
    """Tests for multi-event sequence matching."""

    def test_brute_force_detection(self):
        matcher = SequenceMatcher()

        # Simulate brute force attack
        events = [
            {"class_uid": 3002, "status_id": 9, "src_endpoint": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "time": "2024-01-01T00:00:00Z"},
            {"class_uid": 3002, "status_id": 9, "src_endpoint": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "time": "2024-01-01T00:00:10Z"},
            {"class_uid": 3002, "status_id": 9, "src_endpoint": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "time": "2024-01-01T00:00:20Z"},
            {"class_uid": 3002, "status_id": 1, "src_endpoint": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "time": "2024-01-01T00:00:30Z"},
        ]

        alerts = []
        for event in events:
            alerts.extend(matcher.process(event))

        assert len(alerts) == 1
        assert alerts[0].title == "Brute Force Attack"
        assert "T1110.001" in alerts[0].mitre_techniques

    def test_no_false_positive_single_failure(self):
        matcher = SequenceMatcher()

        # Single failed login should not trigger
        event = {"class_uid": 3002, "status_id": 9, "src_endpoint": {"ip": "1.2.3.4"}, "user": {"name": "admin"}, "time": "2024-01-01T00:00:00Z"}
        alerts = matcher.process(event)

        assert len(alerts) == 0
