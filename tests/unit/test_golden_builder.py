"""Tests for golden_builder module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.evaluate.golden_builder import (
    GoldenBuilder,
    GoldenCandidate,
    build_golden_suite,
)


class TestGoldenCandidate:
    """Tests for GoldenCandidate dataclass."""

    def test_to_golden_entry(self):
        """GoldenCandidate serializes to golden_logs.json format."""
        candidate = GoldenCandidate(
            name="Test Auth — sshd (login success...)",
            raw_log='{"timestamp": "2024-01-01T00:00:00Z", "event": "login", "user": "alice"}',
            class_uid=3002,
            class_name="Authentication",
            expected={"user": "alice", "src_endpoint": {"ip": "192.168.1.1"}},
            trust_score=0.92,
            field_count=2,
            extraction_methods=["pattern", "alias"],
            log_format="syslog_json",
        )

        entry = candidate.to_golden_entry()

        assert entry["name"] == "Test Auth — sshd (login success...)"
        assert entry["raw_log"] == candidate.raw_log
        assert entry["class_uid"] == 3002
        assert entry["expected"] == {"user": "alice", "src_endpoint": {"ip": "192.168.1.1"}}
        assert entry["trust_score"] == 0.92
        assert entry["log_format"] == "syslog_json"


class TestGoldenBuilder:
    """Tests for GoldenBuilder validation pipeline."""

    def test_init_loads_extractors(self):
        """GoldenBuilder initializes pattern extractor and validators."""
        builder = GoldenBuilder()

        assert builder._pattern_extractor is not None
        assert builder._hallucination_checker is not None
        assert builder._coercer is not None
        assert builder._validator is not None

    def test_fingerprint_log_deduplication(self):
        """Same log produces same fingerprint."""
        log1 = "sshd[123]: Accepted password for alice from 192.168.1.1"
        log2 = "sshd[123]: Accepted password for alice from 192.168.1.1"
        log3 = "sshd[456]: Accepted password for bob from 192.168.1.2"

        fp1 = GoldenBuilder._fingerprint_log(log1)
        fp2 = GoldenBuilder._fingerprint_log(log2)
        fp3 = GoldenBuilder._fingerprint_log(log3)

        assert fp1 == fp2
        assert fp1 != fp3

    def test_fingerprint_log_truncation(self):
        """Fingerprint uses first 200 chars."""
        long_log = "x" * 300
        fp = GoldenBuilder._fingerprint_log(long_log)
        assert len(fp) == 200

    def test_is_temporal_valid_epoch(self):
        """Validates epoch timestamps in range 2000-2030."""
        # Valid epoch (2024-01-01)
        assert GoldenBuilder._is_temporal_valid(1704067200) is True
        # Invalid epoch (1990)
        assert GoldenBuilder._is_temporal_valid(631152000) is False
        # Invalid epoch (future)
        assert GoldenBuilder._is_temporal_valid(2000000000) is False

    def test_is_temporal_valid_iso8601(self):
        """Validates ISO8601 timestamps in range 2000-2030."""
        # Valid ISO8601
        assert GoldenBuilder._is_temporal_valid("2024-01-01T00:00:00Z") is True
        # Invalid ISO8601 (future)
        assert GoldenBuilder._is_temporal_valid("2040-01-01T00:00:00Z") is False

    def test_is_temporal_valid_syslog_date(self):
        """Syslog dates (no year) always pass."""
        assert GoldenBuilder._is_temporal_valid("Jan  1 00:00:00") is True

    def test_semantic_coherence_auth_category(self):
        """Auth events should have user or actor fields."""
        event = {"user": "alice", "status": "success"}
        score = GoldenBuilder._check_semantic_coherence(event, class_uid=3002)
        assert score == 1.0

        event_no_user = {"status": "success"}
        score = GoldenBuilder._check_semantic_coherence(event_no_user, class_uid=3002)
        assert score == 0.0

    def test_semantic_coherence_network_category(self):
        """Network events should have endpoint fields."""
        event_with_endpoint = {"src_endpoint": {"ip": "192.168.1.1"}}
        score = GoldenBuilder._check_semantic_coherence(event_with_endpoint, class_uid=4001)
        assert score == 1.0

        event_no_endpoint = {"protocol": "TCP"}
        score = GoldenBuilder._check_semantic_coherence(event_no_endpoint, class_uid=4001)
        assert score == 0.0

    def test_semantic_coherence_activity_status_consistency(self):
        """Activity/status consistency check."""
        # Event with activity_id and status but no user (category 3 check fails)
        # Activity/status check passes since status_id is None
        event = {"activity_id": 1, "status": "success"}
        score = GoldenBuilder._check_semantic_coherence(event, class_uid=3002)
        # 2 checks: category (fail, no user) + activity/status (pass)
        assert score == 0.5

        # Event with severity_id in valid range but no user (category 3 check fails)
        event = {"severity_id": 3}
        score = GoldenBuilder._check_semantic_coherence(event, class_uid=3002)
        # 2 checks: category (fail, no user) + severity (pass)
        assert score == 0.5

        # Event with user and valid severity (both pass)
        event = {"user": "alice", "severity_id": 3}
        score = GoldenBuilder._check_semantic_coherence(event, class_uid=3002)
        # 2 checks: category (pass) + severity (pass)
        assert score == 1.0

    def test_generate_name(self):
        """Generates human-readable name from class, format, and log."""
        name = GoldenBuilder._generate_name(
            "Authentication",
            "syslog_json",
            '{"timestamp": "2024-01-01", "app": "sshd", "message": "login"}',
        )
        assert "Authentication" in name
        assert "sshd" in name

    def test_build_fingerprint_set(self):
        """Builds deduplication set from golden entries."""
        golden = [
            {"raw_log": "entry one"},
            {"raw_log": "entry two"},
            {"raw_log": "entry one"},  # duplicate
        ]
        builder = GoldenBuilder()
        fp_set = builder._build_fingerprint_set(golden)
        assert len(fp_set) == 2
        assert "entry one" in fp_set
        assert "entry two" in fp_set


class TestBuildGoldenSuite:
    """Tests for build_golden_suite CLI function."""

    @patch("shrike.evaluate.golden_builder.GoldenBuilder")
    def test_build_golden_suite_returns_count(self, mock_builder_class):
        """Returns number of new entries added."""
        mock_builder = MagicMock()
        mock_candidate = MagicMock()
        mock_candidate.to_golden_entry.return_value = {"name": "test"}
        mock_builder.build_candidates.return_value = [mock_candidate]
        mock_builder_class.return_value = mock_builder

        with patch("builtins.open", MagicMock()):
            with patch("json.load", return_value=[]):
                with patch("json.loads", return_value={"raw_log": "test", "class_uid": 3002}):
                    count = build_golden_suite(
                        ground_truth_path="/tmp/gt.jsonl",
                        existing_golden_path="/tmp/golden.json",
                        output_path="/tmp/out.json",
                    )

        assert count == 1
        mock_builder.build_candidates.assert_called_once()