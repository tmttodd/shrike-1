"""Tests for CorrelationEngine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shrike.detect.correlation_engine import CorrelationEngine


class TestCorrelationEngine:
    """Tests for CorrelationEngine."""

    def test_init_defaults(self):
        """Engine initializes with defaults when no config provided."""
        engine = CorrelationEngine()
        assert engine.enabled is True
        assert engine._sigma_engine is None

    def test_init_disabled(self):
        """Engine can be disabled at init."""
        engine = CorrelationEngine(enabled=False)
        assert engine.enabled is False

    def test_process_disabled_returns_empty(self):
        """process() returns empty list when disabled."""
        engine = CorrelationEngine(enabled=False)
        alerts = engine.process({"class_uid": 3002})
        assert alerts == []

    def test_process_no_sigma_engine_returns_empty(self):
        """process() returns empty list when no sigma engine loaded."""
        engine = CorrelationEngine()
        alerts = engine.process({"class_uid": 3002})
        assert alerts == []

    def test_process_with_sigma_engine(self):
        """process() delegates to sigma engine."""
        engine = CorrelationEngine()

        mock_alert = MagicMock()
        mock_sigma_engine = MagicMock()
        mock_sigma_engine.match.return_value = [mock_alert]
        engine._sigma_engine = mock_sigma_engine

        event = {"class_uid": 3002, "user": "alice"}
        alerts = engine.process(event)

        mock_sigma_engine.match.assert_called_once_with(event)
        assert alerts == [mock_alert]

    def test_process_batch(self):
        """process_batch() processes all events."""
        engine = CorrelationEngine()

        mock_alert = MagicMock()
        mock_sigma_engine = MagicMock()
        mock_sigma_engine.match.side_effect = [[], [mock_alert], []]
        engine._sigma_engine = mock_sigma_engine

        events = [{"n": 1}, {"n": 2}, {"n": 3}]
        alerts = engine.process_batch(events)

        assert mock_sigma_engine.match.call_count == 3
        assert alerts == [mock_alert]

    def test_add_sigma_rules_new_engine(self):
        """add_sigma_rules() creates engine if none exists."""
        engine = CorrelationEngine()
        assert engine._sigma_engine is None

        with patch("shrike.detect.correlation_engine.SigmaRuleEngine") as MockEngine:
            mock_instance = MagicMock()
            MockEngine.return_value = mock_instance
            engine.add_sigma_rules("/tmp/rules")
            MockEngine.assert_called_once_with(rules_dir="/tmp/rules")
            assert engine._sigma_engine == mock_instance

    def test_add_sigma_rules_existing_engine(self):
        """add_sigma_rules() delegates to existing engine."""
        engine = CorrelationEngine()
        mock_engine = MagicMock()
        engine._sigma_engine = mock_engine

        engine.add_sigma_rules("/tmp/rules")
        mock_engine.load_rules.assert_called_once_with("/tmp/rules")

    def test_get_stats_disabled(self):
        """get_stats() shows disabled state."""
        engine = CorrelationEngine(enabled=False)
        stats = engine.get_stats()
        assert stats["enabled"] is False
        assert stats["sigma_rules_loaded"] == 0

    def test_get_stats_with_sigma_rules(self):
        """get_stats() shows sigma rule count."""
        engine = CorrelationEngine()
        mock_engine = MagicMock()
        mock_engine.rules = [{"name": "rule1"}, {"name": "rule2"}]
        engine._sigma_engine = mock_engine

        stats = engine.get_stats()
        assert stats["sigma_rules_loaded"] == 2

    def test_load_config_enables(self):
        """_load_config() enables correlation from YAML config."""
        with patch("builtins.open", MagicMock()):
            with patch("yaml.safe_load", return_value={"correlation": {"enabled": True}}):
                engine = CorrelationEngine(config_path="/tmp/config.yaml")
                assert engine.enabled is True

    def test_load_config_disables(self):
        """_load_config() disables correlation from YAML config."""
        with patch("builtins.open", MagicMock()):
            with patch("yaml.safe_load", return_value={"correlation": {"enabled": False}}):
                engine = CorrelationEngine(config_path="/tmp/config.yaml")
                assert engine.enabled is False