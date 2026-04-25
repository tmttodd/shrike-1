"""Tests for OCSFCoercer."""

from __future__ import annotations

import pytest

from shrike.evaluate.coercion import OCSFCoercer


class TestOCSFCoercer:
    """Tests for OCSFCoercer."""

    def test_coerce_ip(self):
        """Coerces IP address fields."""
        coercer = OCSFCoercer()
        assert coercer.coerce("src_endpoint.ip", "192.168.1.1") == "192.168.1.1"
        assert coercer.coerce("dst_endpoint.ip", "10.0.0.1") == "10.0.0.1"

    def test_coerce_port(self):
        """Coerces port fields."""
        coercer = OCSFCoercer()
        assert coercer.coerce("src_endpoint.port", "22") == 22
        assert coercer.coerce("dst_endpoint.port", "8080") == 8080

    def test_coerce_port_from_string(self):
        """Coerces port from '22/tcp' format."""
        coercer = OCSFCoercer()
        assert coercer.coerce("src_endpoint.port", "22/tcp") == 22

    def test_coerce_integer(self):
        """Coerces integer fields."""
        coercer = OCSFCoercer()
        assert coercer.coerce("process.pid", "1234") == 1234
        assert coercer.coerce("metadata.count", "42") == 42

    def test_coerce_timestamp(self):
        """Coerces timestamp fields."""
        coercer = OCSFCoercer()
        result = coercer.coerce("time", "2024-03-15T10:00:00Z")
        assert result is not None

    def test_coerce_string_passthrough(self):
        """String fields pass through unchanged."""
        coercer = OCSFCoercer()
        assert coercer.coerce("user", "alice") == "alice"

    def test_coerce_unknown_field(self):
        """Unknown fields pass through unchanged."""
        coercer = OCSFCoercer()
        assert coercer.coerce("completely_unknown_field", "some value") == "some value"

    def test_evaluate_batch(self):
        """evaluate_batch() scores a list of results."""
        coercer = OCSFCoercer()
        results = [
            ({"src_endpoint.ip": "192.168.1.1"}, {"src_endpoint.ip": "192.168.1.1"}),
            ({"src_endpoint.port": "22"}, {"src_endpoint.port": 22}),
        ]
        score = coercer.evaluate_batch(results)
        assert isinstance(score, float)
        assert 0 <= score <= 100