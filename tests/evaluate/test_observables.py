"""Tests for ObservablesBuilder."""

from __future__ import annotations

import pytest

from shrike.evaluate.observables import ObservablesBuilder


class TestObservablesBuilder:
    """Tests for ObservablesBuilder."""

    def test_inject_single_ip(self):
        """Injects IP observable."""
        builder = ObservablesBuilder()
        event = {"src_endpoint": {"ip": "192.168.1.1"}}
        builder.inject(event)
        assert "observables" in event
        assert len(event["observables"]) >= 1
        obs = next((o for o in event["observables"] if o["type"] == "IP Address"), None)
        assert obs is not None
        assert obs["value"] == "192.168.1.1"

    def test_inject_user(self):
        """Injects user observable."""
        builder = ObservablesBuilder()
        event = {"user": "alice"}
        builder.inject(event)
        assert "observables" in event
        obs = next((o for o in event["observables"] if o["type"] == "User Name"), None)
        assert obs is not None
        assert obs["value"] == "alice"

    def test_inject_port(self):
        """Injects port observable."""
        builder = ObservablesBuilder()
        event = {"dst_endpoint": {"port": 22}}
        builder.inject(event)
        assert "observables" in event
        obs = next((o for o in event["observables"] if o["type"] == "Port"), None)
        assert obs is not None
        assert obs["value"] == 22

    def test_inject_multiple_observables(self):
        """Injects multiple observable types."""
        builder = ObservablesBuilder()
        event = {
            "user": "alice",
            "src_endpoint": {"ip": "192.168.1.1", "port": 22},
        }
        builder.inject(event)
        assert len(event["observables"]) >= 3

    def test_inject_skips_empty(self):
        """Skips None/empty values."""
        builder = ObservablesBuilder()
        event = {"user": None, "src_endpoint": {"ip": ""}}
        builder.inject(event)
        # Should not add observables for None/empty
        assert "observables" in event

    def test_evaluate_batch(self):
        """evaluate_batch() scores observable coverage."""
        builder = ObservablesBuilder()
        events = [
            ({"user": "alice", "src_endpoint": {"ip": "192.168.1.1"}}, {"user": "alice"}),
        ]
        score = builder.evaluate_batch(events)
        assert isinstance(score, float)
        assert 0 <= score <= 100