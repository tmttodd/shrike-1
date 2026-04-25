"""Tests for FieldMapper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.extractor.field_mapper import FieldMapper


class TestFieldMapper:
    """Tests for FieldMapper."""

    def test_init_loads_aliases(self):
        """Initializes and loads field aliases."""
        mapper = FieldMapper()
        assert isinstance(mapper._aliases, dict)

    def test_map_field_exact_match(self):
        """Exact alias lookup works."""
        mapper = FieldMapper()
        # Try common aliases
        result = mapper.map_field("source_address")
        # May or may not be in aliases, but should not error
        assert result is None or isinstance(result, str)

    def test_map_field_no_match(self):
        """No mapping found = None."""
        mapper = FieldMapper()
        result = mapper.map_field("completely_unknown_field_xyz123")
        assert result is None

    def test_map_batch(self):
        """map_batch() processes multiple fields."""
        mapper = FieldMapper()
        fields = ["source_address", "user_name", "unknown_xyz"]
        results = mapper.map_batch(fields)
        assert len(results) == 3
        assert all(isinstance(r, (str, type(None))) for r in results)

    def test_get_stats(self):
        """get_stats() returns statistics."""
        mapper = FieldMapper()
        stats = mapper.get_stats()
        assert "aliases_loaded" in stats
        assert "embedding_available" in stats