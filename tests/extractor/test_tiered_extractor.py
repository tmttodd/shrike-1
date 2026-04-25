"""Tests for TieredExtractor and PreparseExtractor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shrike.extractor.tiered_extractor import (
    PreparseExtractor,
    TieredExtractor,
)
from shrike.extractor.schema_injected_extractor import ExtractionResult


class TestTieredExtractor:
    """Tests for TieredExtractor."""

    def test_init_default(self):
        """Initializes with all tiers."""
        extractor = TieredExtractor()
        assert extractor._pattern_extractor is not None
        assert extractor._preparse_extractor is not None
        assert extractor._schema_extractor is not None

    def test_init_no_llm(self):
        """Initializes without LLM (pattern-only mode)."""
        extractor = TieredExtractor(llm_url=None)
        assert extractor._preparse_extractor is None
        assert extractor._schema_extractor is None

    def test_extract_pattern_hit(self):
        """Pattern match returns immediately without LLM call."""
        extractor = TieredExtractor()

        mock_result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            method="pattern",
            confidence=0.95,
        )
        with patch.object(extractor._pattern_extractor, "extract", return_value=mock_result):
            result = extractor.extract("sshd: Accepted password for alice")
            assert result is mock_result
            assert result.method == "pattern"

    def test_extract_falls_through_to_llm(self):
        """No pattern match falls through to LLM tiers."""
        extractor = TieredExtractor()

        # Pattern miss
        with patch.object(extractor._pattern_extractor, "extract", return_value=None):
            # Preparse miss
            with patch.object(extractor._preparse_extractor, "extract", return_value=None):
                # Schema hit
                mock_result = ExtractionResult(
                    event={"class_uid": 3002, "user": "alice"},
                    method="schema_injected",
                    confidence=0.8,
                )
                with patch.object(extractor._schema_extractor, "extract", return_value=mock_result):
                    result = extractor.extract("unknown log format")
                    assert result is mock_result
                    assert result.method == "schema_injected"

    def test_extract_all_tiers_fail(self):
        """All tiers fail = None result."""
        extractor = TieredExtractor()

        with patch.object(extractor._pattern_extractor, "extract", return_value=None):
            with patch.object(extractor._preparse_extractor, "extract", return_value=None):
                with patch.object(extractor._schema_extractor, "extract", return_value=None):
                    result = extractor.extract("unknown log format")
                    assert result is None

    def test_get_stats(self):
        """get_stats() returns tier statistics."""
        extractor = TieredExtractor()
        stats = extractor.get_stats()
        assert "tier_hits" in stats
        assert "tier_latency_ms" in stats
        assert "cache_hit_rate" in stats


class TestPreparseExtractor:
    """Tests for PreparseExtractor."""

    def test_init(self):
        """Initializes with LLM URL."""
        extractor = PreparseExtractor(llm_url="http://localhost:11434/v1")
        assert extractor._llm_url is not None

    def test_init_no_llm(self):
        """Initializes without LLM."""
        extractor = PreparseExtractor(llm_url=None)
        assert extractor._llm_url is None

    def test_extract_no_llm(self):
        """No LLM configured = None."""
        extractor = PreparseExtractor(llm_url=None)
        result = extractor.extract("any log")
        assert result is None

    def test_extract_llm_returns_result(self):
        """LLM returns extraction result."""
        extractor = PreparseExtractor(llm_url="http://localhost:11434/v1")

        mock_result = ExtractionResult(
            event={"class_uid": 3002, "user": "alice"},
            method="preparse",
            confidence=0.75,
        )
        with patch.object(extractor, "_call_llm", AsyncMock(return_value=mock_result)):
            result = extractor.extract("sshd: Accepted password for alice")
            assert result is mock_result

    def test_build_schema_context(self):
        """_build_schema_context() returns prompt text."""
        from shrike.extractor.tiered_extractor import _build_schema_context
        context = _build_schema_context(class_uid=3002)
        assert isinstance(context, str)
        assert len(context) > 0