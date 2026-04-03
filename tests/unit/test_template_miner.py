"""Tests for LogTemplateMiner persistence (save/load round-trip)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shrike.extractor.template_miner import LogTemplateMiner, LearnedTemplate, VariableSlot


# Sample syslog-style logs that Drain3 can cluster
SAMPLE_LOGS = [
    "Mar 15 10:00:01 webserver sshd[1234]: Accepted password for alice from 192.168.1.10 port 52341",
    "Mar 15 10:00:02 webserver sshd[1235]: Accepted password for bob from 192.168.1.11 port 52342",
    "Mar 15 10:00:03 webserver sshd[1236]: Accepted password for carol from 192.168.1.12 port 52343",
    "Mar 15 10:00:04 webserver sshd[1237]: Accepted password for dave from 10.0.0.5 port 40001",
    "Mar 15 10:00:05 webserver sshd[1238]: Accepted password for eve from 10.0.0.6 port 40002",
    "Mar 15 10:01:01 webserver sshd[1300]: Failed password for root from 203.0.113.1 port 55555",
    "Mar 15 10:01:02 webserver sshd[1301]: Failed password for root from 203.0.113.2 port 55556",
    "Mar 15 10:01:03 webserver sshd[1302]: Failed password for admin from 203.0.113.3 port 55557",
]


@pytest.fixture
def trained_miner():
    """Create a miner trained on sample logs."""
    miner = LogTemplateMiner(sim_threshold=0.4, depth=4)
    miner.train(SAMPLE_LOGS)
    return miner


@pytest.fixture
def tmp_cache_path(tmp_path):
    """Return a temporary path for the template cache file."""
    return tmp_path / "template_cache.json"


class TestLogTemplateMinerPersistence:
    """Test save/load round-trip for learned templates."""

    def test_save_creates_file(self, trained_miner, tmp_cache_path):
        """save() creates a JSON file on disk."""
        trained_miner.save(tmp_cache_path)
        assert tmp_cache_path.exists()

        data = json.loads(tmp_cache_path.read_text())
        assert data["version"] == 1
        assert isinstance(data["templates"], list)
        assert isinstance(data["drain_clusters"], list)
        assert len(data["templates"]) > 0

    def test_save_creates_parent_dirs(self, trained_miner, tmp_path):
        """save() creates intermediate directories if they don't exist."""
        deep_path = tmp_path / "a" / "b" / "c" / "cache.json"
        trained_miner.save(deep_path)
        assert deep_path.exists()

    def test_save_none_path_is_noop(self, trained_miner):
        """save(None) with no save_path is a safe no-op."""
        trained_miner.save(None)  # Should not raise

    def test_load_restores_template_count(self, trained_miner, tmp_cache_path):
        """Loading a saved cache restores the same number of templates."""
        original_count = trained_miner.template_count
        assert original_count > 0, "Miner should learn templates from sample logs"

        trained_miner.save(tmp_cache_path)

        new_miner = LogTemplateMiner()
        loaded_count = new_miner.load(tmp_cache_path)
        assert loaded_count == original_count

    def test_load_restores_template_strings(self, trained_miner, tmp_cache_path):
        """Loading preserves the template strings."""
        original_templates = {t.template_str for t in trained_miner.templates}
        trained_miner.save(tmp_cache_path)

        new_miner = LogTemplateMiner()
        new_miner.load(tmp_cache_path)

        restored_templates = {t.template_str for t in new_miner.templates}
        assert original_templates == restored_templates

    def test_load_restores_variable_slots(self, trained_miner, tmp_cache_path):
        """Loading preserves variable slot metadata (position, entity_type, ocsf_hint)."""
        trained_miner.save(tmp_cache_path)

        new_miner = LogTemplateMiner()
        new_miner.load(tmp_cache_path)

        for orig_t in trained_miner.templates:
            # Find matching template in restored miner
            matches = [t for t in new_miner.templates if t.template_str == orig_t.template_str]
            assert len(matches) == 1, f"Template '{orig_t.template_str}' not found after load"
            restored_t = matches[0]

            assert len(restored_t.variables) == len(orig_t.variables)
            for orig_v, rest_v in zip(orig_t.variables, restored_t.variables):
                assert rest_v.position == orig_v.position
                assert rest_v.entity_type == orig_v.entity_type
                assert rest_v.ocsf_hint == orig_v.ocsf_hint

    def test_load_restores_cluster_sizes(self, trained_miner, tmp_cache_path):
        """Loading preserves cluster size counts."""
        original_sizes = {t.template_str: t.cluster_size for t in trained_miner.templates}
        trained_miner.save(tmp_cache_path)

        new_miner = LogTemplateMiner()
        new_miner.load(tmp_cache_path)

        for t in new_miner.templates:
            assert t.cluster_size == original_sizes[t.template_str]

    def test_extraction_after_load_matches_original(self, trained_miner, tmp_cache_path):
        """A loaded miner produces the same extraction results as the original."""
        test_log = "Mar 15 10:05:00 webserver sshd[2000]: Accepted password for frank from 172.16.0.1 port 60000"

        original_result = trained_miner.extract(test_log)
        trained_miner.save(tmp_cache_path)

        new_miner = LogTemplateMiner()
        new_miner.load(tmp_cache_path)
        loaded_result = new_miner.extract(test_log)

        # Both should either match or not; if they match, fields should be identical
        if original_result is not None:
            assert loaded_result is not None, "Loaded miner should match same templates"
            assert set(original_result.keys()) == set(loaded_result.keys())
            for key in original_result:
                assert original_result[key] == loaded_result[key], f"Field {key} differs"
        else:
            # Original didn't match — loaded shouldn't either (or it's fine if it does
            # via Drain3 reconstruction). Just verify no crash.
            pass

    def test_save_path_auto_load_on_init(self, trained_miner, tmp_cache_path):
        """save_path parameter triggers auto-load when file exists."""
        trained_miner.save(tmp_cache_path)

        auto_miner = LogTemplateMiner(save_path=tmp_cache_path)
        assert auto_miner.template_count == trained_miner.template_count

    def test_save_path_no_file_no_error(self, tmp_path):
        """save_path pointing to non-existent file doesn't error on init."""
        missing = tmp_path / "does_not_exist.json"
        miner = LogTemplateMiner(save_path=missing)
        assert miner.template_count == 0

    def test_load_nonexistent_returns_zero(self):
        """load() on a missing file returns 0."""
        miner = LogTemplateMiner()
        result = miner.load(Path("/tmp/nonexistent_shrike_test_file.json"))
        assert result == 0

    def test_load_corrupt_json_returns_zero(self, tmp_path):
        """load() on a corrupt file returns 0 gracefully."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{")
        miner = LogTemplateMiner()
        result = miner.load(bad_file)
        assert result == 0

    def test_load_wrong_version_returns_zero(self, tmp_path):
        """load() rejects unknown version numbers."""
        wrong_ver = tmp_path / "wrong_ver.json"
        wrong_ver.write_text(json.dumps({"version": 999}))
        miner = LogTemplateMiner()
        result = miner.load(wrong_ver)
        assert result == 0

    def test_round_trip_json_structure(self, trained_miner, tmp_cache_path):
        """Verify the saved JSON has the expected top-level structure."""
        trained_miner.save(tmp_cache_path)
        data = json.loads(tmp_cache_path.read_text())

        assert set(data.keys()) == {"version", "sim_threshold", "depth", "templates", "drain_clusters", "var_values"}

        for tmpl in data["templates"]:
            assert "cluster_id" in tmpl
            assert "template_str" in tmpl
            assert "cluster_size" in tmpl
            assert "variables" in tmpl
            assert "static_tokens" in tmpl
            for v in tmpl["variables"]:
                assert "position" in v
                assert "entity_type" in v
                assert "ocsf_hint" in v

    def test_multiple_save_load_cycles(self, tmp_cache_path):
        """Multiple save/load cycles don't degrade data."""
        miner = LogTemplateMiner()
        miner.train(SAMPLE_LOGS)
        original_count = miner.template_count
        original_templates = {t.template_str for t in miner.templates}

        for _ in range(3):
            miner.save(tmp_cache_path)
            miner = LogTemplateMiner()
            miner.load(tmp_cache_path)

        assert miner.template_count == original_count
        assert {t.template_str for t in miner.templates} == original_templates
