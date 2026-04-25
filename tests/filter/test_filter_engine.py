"""Tests for FilterEngine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from shrike.filter.filter_engine import FilterEngine, FilterPack, FilterResult


class TestFilterPack:
    """Tests for FilterPack."""

    def test_from_yaml(self, tmp_path: Path):
        """Loads filter pack from YAML."""
        yaml_content = """
name: test-pack
description: Test filter pack
rules:
  - keep: {classes: [3002]}
  - drop: {all: true}
"""
        path = tmp_path / "test.yaml"
        path.write_text(yaml_content)

        pack = FilterPack.from_yaml(path)
        assert pack.name == "test-pack"
        assert pack.description == "Test filter pack"
        assert len(pack.rules) == 2


class TestFilterEngine:
    """Tests for FilterEngine."""

    def test_init(self):
        """Initializes with filter packs directory."""
        engine = FilterEngine()
        assert engine._packs == {}

    def test_load_pack(self, tmp_path: Path):
        """Loads a filter pack."""
        yaml_content = """
name: test
rules:
  - keep: {classes: [3002]}
"""
        path = tmp_path / "test.yaml"
        path.write_text(yaml_content)

        engine = FilterEngine(packs_dir=str(tmp_path))
        assert "test" in engine._packs

    def test_evaluate_keep_class(self):
        """Keeps events matching class filter."""
        engine = FilterEngine()
        event = {"class_uid": 3002, "class_name": "Authentication"}
        result = engine.evaluate(event, pack_name="security-focused")
        assert result.action == "keep"

    def test_evaluate_drop_class(self):
        """Drops events not matching class filter."""
        engine = FilterEngine()
        event = {"class_uid": 0}
        result = engine.evaluate(event, pack_name="security-focused")
        assert result.action == "drop"

    def test_evaluate_no_pack(self):
        """No pack = default keep."""
        engine = FilterEngine()
        event = {"class_uid": 3002}
        result = engine.evaluate(event, pack_name="nonexistent")
        assert result.action == "keep"

    def test_list_packs(self):
        """Lists available filter packs."""
        engine = FilterEngine()
        packs = engine.list_packs()
        assert isinstance(packs, list)

    def test_get_stats(self):
        """get_stats() returns statistics."""
        engine = FilterEngine()
        stats = engine.get_stats()
        assert "packs_loaded" in stats
        assert "evaluations" in stats