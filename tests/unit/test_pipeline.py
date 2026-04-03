"""Tests for Shrike pipeline orchestration.

Tests the pipeline wiring without requiring a trained classifier or extractor LLM.
Uses mocked/stubbed backends for classifier and extractor stages.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shrike.pipeline import ShrikePipeline, PipelineResult
from shrike.detector.format_detector import LogFormat


# Sample log lines for testing
SAMPLE_SYSLOG = '<134>1 2026-03-29T10:00:00Z host sshd 1234 - - Accepted password for user1 from 192.168.1.100 port 22'
SAMPLE_CEF = 'CEF:0|Security|IDS|1.0|100|Alert|5|src=192.168.1.1 dst=10.0.0.1'
SAMPLE_JSON = '{"EventID": 4624, "Channel": "Security", "Computer": "DC01", "Description": "An account was successfully logged on."}'
SAMPLE_CLF = '192.168.1.1 - admin [29/Mar/2026:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234'


class TestPipelineResult:
    """Test PipelineResult data class."""

    def test_dropped_property(self):
        result = PipelineResult(raw_log="test", log_format=LogFormat.CUSTOM, filter_action="drop")
        assert result.dropped

    def test_kept_property(self):
        result = PipelineResult(raw_log="test", log_format=LogFormat.CUSTOM, filter_action="keep")
        assert not result.dropped

    def test_to_dict(self):
        result = PipelineResult(
            raw_log="test log",
            log_format=LogFormat.SYSLOG_RFC5424,
            class_uid=3002,
            class_name="Authentication",
            event={"class_uid": 3002, "user": {"name": "admin"}},
            valid=True,
            field_coverage=0.75,
        )
        d = result.to_dict()
        assert d["event"]["class_uid"] == 3002
        assert d["metadata"]["log_format"] == "syslog_rfc5424"
        assert d["metadata"]["valid"] is True


class TestPipelineDetection:
    """Test Stage 1 (format detection) within the pipeline."""

    def test_pipeline_creates_without_classifier(self):
        """Pipeline can be created without a classifier model."""
        pipe = ShrikePipeline(classifier_model=None)
        assert pipe is not None

    def test_detect_stage_runs(self):
        """Format detection stage runs and populates result."""
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_SYSLOG)
        assert result.log_format == LogFormat.SYSLOG_RFC5424
        assert result.detect_ms >= 0

    def test_detect_cef(self):
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_CEF)
        assert result.log_format == LogFormat.CEF

    def test_detect_json(self):
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_JSON)
        assert result.log_format == LogFormat.WINDOWS_EVTX_JSON

    def test_detect_clf(self):
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_CLF)
        assert result.log_format == LogFormat.CLF


class TestPipelineFilter:
    """Test Stage 3 (filter) within the pipeline."""

    def test_default_filter_keeps_everything(self):
        """Default all-pass filter keeps everything."""
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_SYSLOG)
        assert result.filter_action == "keep"

    def test_filter_timing(self):
        """Filter stage has non-negative timing."""
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_SYSLOG)
        assert result.filter_ms >= 0


class TestPipelineNoClassifier:
    """Test pipeline behavior when no classifier is loaded."""

    def test_defaults_to_base_event(self):
        """Without a classifier, class defaults to 0 (Base Event)."""
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_SYSLOG)
        assert result.class_uid == 0
        assert result.classification_confidence == 0.0

    def test_total_timing_populated(self):
        """Total timing is populated."""
        pipe = ShrikePipeline(classifier_model=None)
        result = pipe.process(SAMPLE_SYSLOG)
        assert result.total_ms > 0


class TestPipelineBatch:
    """Test batch processing."""

    def test_batch_processes_all_lines(self):
        pipe = ShrikePipeline(classifier_model=None)
        logs = [SAMPLE_SYSLOG, SAMPLE_CEF, SAMPLE_JSON, SAMPLE_CLF]
        results = pipe.process_batch(logs)
        assert len(results) == 4

    def test_batch_callback(self):
        pipe = ShrikePipeline(classifier_model=None)
        logs = [SAMPLE_SYSLOG, SAMPLE_CEF]
        calls = []
        results = pipe.process_batch(logs, progress_callback=lambda i, t, r: calls.append(i))
        assert len(calls) == 2

    def test_batch_different_formats(self):
        pipe = ShrikePipeline(classifier_model=None)
        logs = [SAMPLE_SYSLOG, SAMPLE_CEF, SAMPLE_JSON, SAMPLE_CLF]
        results = pipe.process_batch(logs)
        formats = [r.log_format for r in results]
        assert LogFormat.SYSLOG_RFC5424 in formats
        assert LogFormat.CEF in formats
        assert LogFormat.WINDOWS_EVTX_JSON in formats
        assert LogFormat.CLF in formats
