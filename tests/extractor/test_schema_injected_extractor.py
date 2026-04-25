"""Tests for SchemaInjectedExtractor and ExtractionResult."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shrike.extractor.schema_injected_extractor import (
    ExtractionResult,
    SchemaInjectedExtractor,
    _build_schema_context,
    _extract_json,
)


class TestExtractionResult:
    """Tests for ExtractionResult dataclass."""

    def test_init(self):
        """Initializes with required fields."""
        result = ExtractionResult(
            event={"class_uid": 3002},
            method="pattern",
            confidence=0.95,
        )
        assert result.event["class_uid"] == 3002
        assert result.method == "pattern"
        assert result.confidence == 0.95

    def test_init_with_optional_fields(self):
        """Initializes with optional fields."""
        result = ExtractionResult(
            event={"class_uid": 3002},
            method="llm",
            confidence=0.75,
            extraction_time_ms=500.0,
            retries=1,
            error=None,
        )
        assert result.extraction_time_ms == 500.0
        assert result.retries == 1

    def test_confidence_dict(self):
        """confidence can be a dict mapping field → derivation method."""
        result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            method="pattern",
            confidence={"user": "pattern", "src_endpoint.ip": "alias"},
        )
        assert result.confidence["user"] == "pattern"
        assert result.confidence["src_endpoint.ip"] == "alias"


class TestSchemaInjectedExtractor:
    """Tests for SchemaInjectedExtractor."""

    def test_init_no_llm(self):
        """Initializes without LLM (disabled)."""
        extractor = SchemaInjectedExtractor(llm_url=None)
        assert extractor._llm_url is None

    def test_extract_no_llm(self):
        """No LLM = None."""
        extractor = SchemaInjectedExtractor(llm_url=None)
        result = extractor.extract("any log", class_uid=3002)
        assert result is None

    def test_extract_with_mock_llm(self):
        """LLM returns extraction result."""
        extractor = SchemaInjectedExtractor(llm_url="http://localhost:11434/v1")

        mock_result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            method="schema_injected",
            confidence=0.8,
        )
        with patch.object(extractor, "_call_llm", AsyncMock(return_value=mock_result)):
            result = extractor.extract("sshd: Accepted password for alice", class_uid=3002)
            assert result is mock_result

    def test_extract_retries_on_error(self):
        """Retries on LLM error."""
        extractor = SchemaInjectedExtractor(llm_url="http://localhost:11434/v1")

        with patch.object(extractor, "_call_llm", side_effect=[Exception("fail"), Exception("fail"), mock_result := MagicMock()]):
            result = extractor.extract("sshd: Accepted password for alice", class_uid=3002)
            assert extractor._retries == 2


class TestBuildSchemaContext:
    """Tests for _build_schema_context."""

    def test_returns_string(self):
        """Returns a string schema description."""
        schema = {"class_uid": 3002, "class_name": "Authentication"}
        context = _build_schema_context(schema)
        assert isinstance(context, str)
        assert len(context) > 0


class TestExtractJson:
    """Tests for _extract_json helper."""

    def test_extracts_json_from_response(self):
        """Extracts JSON object from LLM response text."""
        response = 'Here is the extraction:\n{"class_uid": 3002, "user": "alice"}\nDone.'
        result = _extract_json(response)
        assert result == {"class_uid": 3002, "user": "alice"}

    def test_handles_markdown_code_block(self):
        """Handles markdown code block wrapper."""
        response = '```json\n{"class_uid": 3002}\n```'
        result = _extract_json(response)
        assert result == {"class_uid": 3002}

    def test_returns_none_on_invalid_json(self):
        """Returns None on invalid JSON."""
        response = "This is not JSON at all"
        result = _extract_json(response)
        assert result is None