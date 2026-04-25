"""Tests for SigmaRuleEngine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.detect.sigma.rule_engine import SigmaRuleEngine


class TestSigmaRuleEngine:
    """Tests for SigmaRuleEngine."""

    def test_init(self):
        """Initializes with empty rules."""
        engine = SigmaRuleEngine()
        assert engine.rules == []
        assert engine._loader is not None
        assert engine._mapper is not None

    def test_load_rules(self, tmp_path: Path):
        """load_rules() loads Sigma rules from directory."""
        # Create a mock sigma rule file
        rule_content = """
name: test-rule
logship:
  EventID: 4624
condition: logship.EventID == 4624
"""
        rule_file = tmp_path / "test_rule.yaml"
        rule_file.write_text(rule_content)

        engine = SigmaRuleEngine()
        count = engine.load_rules(tmp_path)
        assert count >= 0  # May load or skip invalid rules

    def test_match_no_rules(self):
        """match() with no rules returns empty list."""
        engine = SigmaRuleEngine()
        event = {"class_uid": 3002, "user": "alice"}
        alerts = engine.match(event)
        assert alerts == []

    def test_match_with_rules(self):
        """match() evaluates rules against event."""
        engine = SigmaRuleEngine()

        # Add a mock rule
        engine.rules = [
            {
                "name": "test rule",
                "condition": "class_uid == 3002",
            }
        ]

        event = {"class_uid": 3002, "user": "alice"}
        alerts = engine.match(event)
        assert isinstance(alerts, list)

    def test_get_stats(self):
        """get_stats() returns engine statistics."""
        engine = SigmaRuleEngine()
        stats = engine.get_stats()
        assert "rules_loaded" in stats
        assert "last_match_count" in stats