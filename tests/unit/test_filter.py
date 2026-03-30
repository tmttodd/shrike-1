"""Tests for filter engine."""

import pytest
from pathlib import Path

from shrike.filter.filter_engine import FilterPack, FilterEngine, FilterResult


class TestFilterPack:
    """Test FilterPack evaluation."""

    def test_all_pass(self):
        pack = FilterPack.all_pass()
        result = pack.evaluate(class_uid=3002, severity_id=1)
        assert result.action == "keep"

    def test_keep_by_class(self):
        pack = FilterPack(
            name="test",
            rules=[{"keep": {"classes": [3002, 3003]}}],
        )
        assert pack.evaluate(3002).action == "keep"
        assert pack.evaluate(3003).action == "keep"
        assert pack.evaluate(1007).action == "keep"  # default keep

    def test_drop_by_class(self):
        pack = FilterPack(
            name="test",
            rules=[
                {"drop": {"classes": [0]}},
                {"keep": "all"},
            ],
        )
        assert pack.evaluate(0).action == "drop"
        assert pack.evaluate(3002).action == "keep"

    def test_severity_gte(self):
        pack = FilterPack(
            name="test",
            rules=[{"keep": {"severity_id": {"gte": 3}}}],
        )
        assert pack.evaluate(3002, severity_id=3).action == "keep"
        assert pack.evaluate(3002, severity_id=5).action == "keep"
        assert pack.evaluate(3002, severity_id=1).action == "keep"  # default keep

    def test_severity_lte(self):
        pack = FilterPack(
            name="test",
            rules=[
                {"drop": {"severity_id": {"lte": 1}}},
                {"keep": "all"},
            ],
        )
        assert pack.evaluate(3002, severity_id=0).action == "drop"
        assert pack.evaluate(3002, severity_id=1).action == "drop"
        assert pack.evaluate(3002, severity_id=2).action == "keep"

    def test_confidence_threshold(self):
        pack = FilterPack(
            name="test",
            rules=[
                {"drop": {"confidence": {"lte": 0.5}}},
                {"keep": "all"},
            ],
        )
        assert pack.evaluate(3002, confidence=0.3).action == "drop"
        assert pack.evaluate(3002, confidence=0.8).action == "keep"

    def test_category_filter(self):
        pack = FilterPack(
            name="test",
            rules=[{"keep": {"categories": [3]}}],  # IAM category
        )
        assert pack.evaluate(3002).action == "keep"  # 3002 // 1000 = 3
        assert pack.evaluate(1007).action == "keep"  # default keep

    def test_first_match_wins(self):
        pack = FilterPack(
            name="test",
            rules=[
                {"drop": {"classes": [3002]}},
                {"keep": {"classes": [3002]}},  # Should never reach this
            ],
        )
        result = pack.evaluate(3002)
        assert result.action == "drop"
        assert result.rule_index == 0

    def test_default_keep(self):
        """If no rules match, default is keep."""
        pack = FilterPack(
            name="test",
            rules=[{"keep": {"classes": [9999]}}],
        )
        result = pack.evaluate(3002)
        assert result.action == "keep"
        assert result.rule_index == -1


class TestFilterEngine:
    """Test FilterEngine management."""

    def test_available_packs(self):
        engine = FilterEngine()
        # Default has no packs loaded
        assert engine.available_packs == []

    def test_default_keeps_all(self):
        engine = FilterEngine()
        result = engine.evaluate(3002)
        assert result.action == "keep"

    def test_load_from_directory(self):
        filters_dir = Path(__file__).parent.parent.parent / "filters"
        if filters_dir.exists():
            engine = FilterEngine(filters_dir)
            assert len(engine.available_packs) > 0

    def test_set_active_invalid(self):
        engine = FilterEngine()
        with pytest.raises(KeyError):
            engine.set_active("nonexistent")

    def test_load_and_activate(self):
        filters_dir = Path(__file__).parent.parent.parent / "filters"
        if not filters_dir.exists():
            pytest.skip("No filters directory")
        engine = FilterEngine(filters_dir)
        if "all-pass" in engine.available_packs:
            engine.set_active("all-pass")
            result = engine.evaluate(3002)
            assert result.action == "keep"
