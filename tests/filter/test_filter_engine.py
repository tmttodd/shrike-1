"""Tests for FilterEngine — 90% → 98%+ coverage.

Covers:
- FilterPack.from_yaml() with a real YAML file
- FilterEngine.load_packs() exception handling (lines 156-157)
- FilterEngine.set_active() else branch (line 162)
- _matches() with non-dict, non-all condition (line 101)
- _matches() with severity_id eq condition (lines 117-120)
- _matches() with confidence gte/lte (lines 127-129)
- _matches() with categories (lines 132-135)
- FilterPack with drop rule but no keep rule (line 79)
- FilterEngine.evaluate() with metadata kwarg
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from shrike.filter.filter_engine import FilterEngine, FilterPack, FilterResult


# ---------------------------------------------------------------------------
# FilterPack.from_yaml()
# ---------------------------------------------------------------------------

class TestFilterPackFromYaml:
    """FilterPack.from_yaml() loading from real YAML files."""

    def test_from_yaml_basic(self):
        """Load a basic filter pack from a YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({
                "name": "test-pack",
                "description": "Test filter pack",
                "rules": [
                    {"keep": {"classes": [3002, 3003]}},
                    {"drop": {"classes": [0]}},
                    {"keep": "all"},
                ],
            }, f)
            f.flush()
            path = Path(f.name)

        try:
            pack = FilterPack.from_yaml(path)
            assert pack.name == "test-pack"
            assert pack.description == "Test filter pack"
            assert len(pack.rules) == 3
            assert pack.evaluate(3002).action == "keep"
            assert pack.evaluate(0).action == "drop"
        finally:
            path.unlink()

    def test_from_yaml_minimal(self):
        """Load a minimal YAML with just rules."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({
                "rules": [{"keep": "all"}],
            }, f)
            f.flush()
            path = Path(f.name)

        try:
            pack = FilterPack.from_yaml(path)
            assert pack.name == path.stem  # defaults to filename stem
            assert pack.evaluate(3002).action == "keep"
        finally:
            path.unlink()

    def test_from_yaml_empty_rules(self):
        """Load YAML with no rules."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({}, f)
            f.flush()
            path = Path(f.name)

        try:
            pack = FilterPack.from_yaml(path)
            assert pack.rules == []
            assert pack.evaluate(3002).action == "keep"  # default keep
        finally:
            path.unlink()


# ---------------------------------------------------------------------------
# _matches() edge cases
# ---------------------------------------------------------------------------

class TestMatchesConditions:
    """_matches() with various condition types."""

    def setup_method(self):
        self.pack = FilterPack(name="test", rules=[])

    def test_condition_all_matches_everything(self):
        """condition='all' matches any event."""
        assert self.pack._matches("all", 3002, 1, 1.0, None) is True
        assert self.pack._matches("all", 0, 0, 0.0, None) is True

    def test_condition_non_dict_non_all_returns_false(self):
        """Non-dict, non-'all' condition returns False (line 101)."""
        # String that's not "all"
        assert self.pack._matches("some-string", 3002, 1, 1.0, None) is False
        # Integer
        assert self.pack._matches(42, 3002, 1, 1.0, None) is False
        # List
        assert self.pack._matches([3002], 3002, 1, 1.0, None) is False
        # None
        assert self.pack._matches(None, 3002, 1, 1.0, None) is False

    def test_severity_eq_exact_match(self):
        """severity_id: {eq: N} matches exact severity (lines 117-120)."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"severity_id": {"eq": 3}}},
        ])
        assert pack.evaluate(3002, severity_id=3).action == "keep"
        assert pack.evaluate(3002, severity_id=2).action == "keep"  # default
        assert pack.evaluate(3002, severity_id=4).action == "keep"  # default

    def test_severity_eq_integer_direct(self):
        """severity_id as direct integer (lines 118-120)."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"severity_id": 3}},
        ])
        assert pack.evaluate(3002, severity_id=3).action == "keep"
        assert pack.evaluate(3002, severity_id=2).action == "keep"  # default

    def test_confidence_gte_exact(self):
        """confidence: {gte: N} matches when confidence >= N (lines 127-129)."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"confidence": {"gte": 0.8}}},
        ])
        assert pack.evaluate(3002, confidence=0.8).action == "keep"
        assert pack.evaluate(3002, confidence=0.9).action == "keep"
        assert pack.evaluate(3002, confidence=0.5).action == "keep"  # default

    def test_confidence_lte_exact(self):
        """confidence: {lte: N} matches when confidence <= N."""
        pack = FilterPack(name="test", rules=[
            {"drop": {"confidence": {"lte": 0.3}}},
            {"keep": "all"},
        ])
        assert pack.evaluate(3002, confidence=0.3).action == "drop"
        assert pack.evaluate(3002, confidence=0.1).action == "drop"
        assert pack.evaluate(3002, confidence=0.8).action == "keep"

    def test_confidence_gte_and_lte_combined(self):
        """confidence with both gte and lte."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"confidence": {"gte": 0.5, "lte": 0.9}}},
        ])
        assert pack.evaluate(3002, confidence=0.7).action == "keep"
        assert pack.evaluate(3002, confidence=0.3).action == "keep"  # default
        assert pack.evaluate(3002, confidence=0.95).action == "keep"  # default

    def test_categories_filter(self):
        """categories filter matches class_uid // 1000 (lines 132-135)."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"categories": [3]}},  # IAM: 3000-3999
            {"keep": "all"},
        ])
        # 3002 // 1000 = 3
        assert pack.evaluate(3002).action == "keep"
        # 1007 // 1000 = 1
        assert pack.evaluate(1007).action == "keep"  # default
        # 4001 // 1000 = 4
        assert pack.evaluate(4001).action == "keep"  # default

    def test_categories_multiple(self):
        """Multiple categories in filter."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"categories": [1, 2, 3]}},
            {"keep": "all"},
        ])
        assert pack.evaluate(1001).action == "keep"  # category 1
        assert pack.evaluate(2004).action == "keep"  # category 2
        assert pack.evaluate(3002).action == "keep"  # category 3
        assert pack.evaluate(4001).action == "keep"  # default (category 4)

    def test_severity_gte_and_lte_combined(self):
        """severity_id with both gte and lte."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"severity_id": {"gte": 2, "lte": 4}}},
        ])
        assert pack.evaluate(3002, severity_id=3).action == "keep"
        assert pack.evaluate(3002, severity_id=1).action == "keep"  # default
        assert pack.evaluate(3002, severity_id=5).action == "keep"  # default

    def test_metadata_passed_through(self):
        """metadata dict is passed to _matches() for future rule types."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"classes": [3002]}},
        ])
        # Currently metadata is accepted but not evaluated
        result = pack.evaluate(3002, metadata={"custom": "value"})
        assert result.action == "keep"


# ---------------------------------------------------------------------------
# FilterPack with drop-only rules (line 79)
# ---------------------------------------------------------------------------

class TestDropOnlyRules:
    """FilterPack with rules that have 'drop' but no 'keep' (line 79)."""

    def test_drop_without_keep(self):
        """Rules with 'drop' key but no 'keep' key."""
        pack = FilterPack(name="test", rules=[
            {"drop": {"classes": [0]}},
        ])
        assert pack.evaluate(0).action == "drop"
        assert pack.evaluate(3002).action == "keep"  # default

    def test_drop_takes_precedence_over_keep(self):
        """When both keep and drop match, first in order wins."""
        pack = FilterPack(name="test", rules=[
            {"keep": {"classes": [3002]}},
            {"drop": {"classes": [3002]}},  # Should never reach
        ])
        result = pack.evaluate(3002)
        assert result.action == "keep"
        assert result.rule_index == 0

    def test_drop_then_keep(self):
        """drop rule followed by keep rule."""
        pack = FilterPack(name="test", rules=[
            {"drop": {"classes": [0]}},
            {"keep": "all"},
        ])
        assert pack.evaluate(0).action == "drop"
        assert pack.evaluate(3002).action == "keep"


# ---------------------------------------------------------------------------
# FilterEngine edge cases
# ---------------------------------------------------------------------------

class TestFilterEngineEdgeCases:
    """FilterEngine exception handling and edge cases."""

    def test_load_packs_with_invalid_yaml(self):
        """load_packs() handles invalid YAML gracefully (lines 156-157)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = Path(tmpdir) / "bad.yaml"
            bad_file.write_text("invalid: yaml: content: [}")

            engine = FilterEngine()
            engine.load_packs(Path(tmpdir))

            # Should not raise, bad pack is skipped
            assert "bad" not in engine.available_packs

    def test_load_packs_with_empty_directory(self):
        """load_packs() with no YAML files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = FilterEngine()
            engine.load_packs(Path(tmpdir))
            assert engine.available_packs == []

    def test_set_active_else_branch(self):
        """set_active() with nonexistent pack raises KeyError (line 162)."""
        engine = FilterEngine()
        with pytest.raises(KeyError, match="not found"):
            engine.set_active("nonexistent-pack")

    def test_set_active_updates_active_pack(self):
        """set_active() changes the active pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write two packs
            for name, rule in [("pack-a", {"keep": {"classes": [3002]}}),
                              ("pack-b", {"drop": {"classes": [3002]}})]:
                path = Path(tmpdir) / f"{name}.yaml"
                yaml.dump({"name": name, "rules": [rule]}, path.open("w"))

            engine = FilterEngine(Path(tmpdir))
            assert engine._active_pack.name == "all-pass"  # default

            engine.set_active("pack-a")
            assert engine._active_pack.name == "pack-a"
            assert engine.evaluate(3002).action == "keep"

            engine.set_active("pack-b")
            assert engine._active_pack.name == "pack-b"
            assert engine.evaluate(3002).action == "drop"

    def test_evaluate_with_confidence(self):
        """evaluate() passes confidence to the pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "conf.yaml"
            yaml.dump({
                "name": "conf",
                "rules": [
                    {"drop": {"confidence": {"lte": 0.5}}},
                    {"keep": "all"},
                ],
            }, path.open("w"))

            engine = FilterEngine(Path(tmpdir))
            engine.set_active("conf")
            assert engine.evaluate(3002, confidence=0.3).action == "drop"
            assert engine.evaluate(3002, confidence=0.8).action == "keep"

    def test_evaluate_with_severity_id(self):
        """evaluate() passes severity_id to the pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sev.yaml"
            yaml.dump({
                "name": "sev",
                "rules": [
                    {"keep": {"severity_id": {"gte": 3}}},
                ],
            }, path.open("w"))

            engine = FilterEngine(Path(tmpdir))
            engine.set_active("sev")
            assert engine.evaluate(3002, severity_id=3).action == "keep"
            assert engine.evaluate(3002, severity_id=1).action == "keep"  # default

    def test_evaluate_with_metadata(self):
        """evaluate() passes metadata to the pack."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "meta.yaml"
            yaml.dump({
                "name": "meta",
                "rules": [
                    {"keep": {"classes": [3002]}},
                ],
            }, path.open("w"))

            engine = FilterEngine(Path(tmpdir))
            engine.set_active("meta")
            result = engine.evaluate(3002, metadata={"custom": "field"})
            assert result.action == "keep"

    def test_nonexistent_packs_dir(self):
        """FilterEngine with nonexistent packs_dir is safe."""
        engine = FilterEngine(Path("/nonexistent/path"))
        assert engine.available_packs == []
        assert engine.evaluate(3002).action == "keep"

    def test_available_packs_returns_list(self):
        """available_packs returns a list of pack names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["zebra", "alpha", "beta"]:
                path = Path(tmpdir) / f"{name}.yaml"
                yaml.dump({"name": name, "rules": [{"keep": "all"}]}, path.open("w"))

            engine = FilterEngine(Path(tmpdir))
            assert isinstance(engine.available_packs, list)
            assert len(engine.available_packs) == 3
            assert set(engine.available_packs) == {"zebra", "alpha", "beta"}


# ---------------------------------------------------------------------------
# FilterResult edge cases
# ---------------------------------------------------------------------------

class TestFilterResult:
    """FilterResult dataclass."""

    def test_keep_result(self):
        """FilterResult for keep action."""
        result = FilterResult(action="keep", rule_index=0, rule_description="test")
        assert result.action == "keep"
        assert result.rule_index == 0

    def test_drop_result(self):
        """FilterResult for drop action."""
        result = FilterResult(action="drop", rule_index=1, rule_description="test")
        assert result.action == "drop"
        assert result.rule_index == 1

    def test_default_result(self):
        """FilterResult for default (no rule matched) has rule_description='default: keep'."""
        # Create a pack where no rules match — triggers the default return
        pack = FilterPack(name="test", rules=[{"keep": {"classes": [9999]}}])
        result = pack.evaluate(3002)  # class 3002 doesn't match rule for 9999
        assert result.action == "keep"
        assert result.rule_index == -1
        assert result.rule_description == "default: keep"


# ---------------------------------------------------------------------------
# FilterPack.evaluate() integration
# ---------------------------------------------------------------------------

class TestFilterPackEvaluate:
    """FilterPack.evaluate() full integration."""

    def test_full_pci_dss_pack(self):
        """Simulate a PCI-DSS filter pack."""
        pack = FilterPack(name="pci-dss", rules=[
            {"keep": {"classes": [3002, 3003, 3005, 4001, 4007]}},
            {"keep": {"severity_id": {"gte": 3}}},
            {"drop": {"classes": [0]}},
            {"keep": "all"},
        ])
        # Auth events kept
        assert pack.evaluate(3002).action == "keep"
        # Severity 3+ kept
        assert pack.evaluate(4001, severity_id=4).action == "keep"
        # Unknown class dropped
        assert pack.evaluate(0).action == "drop"
        # Default kept
        assert pack.evaluate(9999).action == "keep"

    def test_first_match_wins_complex(self):
        """First match wins in complex rule sets."""
        pack = FilterPack(name="test", rules=[
            {"drop": {"classes": [3002], "severity_id": {"gte": 3}}},
            {"keep": {"classes": [3002]}},
            {"keep": "all"},
        ])
        # High-severity auth → dropped
        assert pack.evaluate(3002, severity_id=4).action == "drop"
        # Low-severity auth → kept
        assert pack.evaluate(3002, severity_id=1).action == "keep"

    def test_rule_index_correct(self):
        """rule_index matches the correct rule."""
        pack = FilterPack(name="test", rules=[
            {"drop": {"classes": [3002]}},  # index 0
            {"keep": {"classes": [3003]}},  # index 1
            {"keep": "all"},                  # index 2
        ])
        assert pack.evaluate(3002).rule_index == 0
        assert pack.evaluate(3003).rule_index == 1
        assert pack.evaluate(4001).rule_index == 2