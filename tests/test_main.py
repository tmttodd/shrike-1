"""Tests for the Shrike main entrypoint."""

from shrike.config import Config


def test_config_from_env(monkeypatch) -> None:
    """Config.from_env() correctly reads all environment variables."""
    monkeypatch.setenv("SHRIKE_MODE", "collector")
    monkeypatch.setenv("SHRIKE_HTTP_PORT", "9090")
    monkeypatch.setenv("SHRIKE_DESTINATIONS", "file_jsonl,splunk_hec")
    monkeypatch.setenv("SHRIKE_WAL_DIR", "/data/test-wal")
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://splunk.example.com:8088")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "test-token-123")
    monkeypatch.setenv("FILE_OUTPUT_DIR", "/data/test-output")

    cfg = Config.from_env()

    assert cfg.mode == "collector"
    assert cfg.http_port == 9090
    assert cfg.destinations == ["file_jsonl", "splunk_hec"]
    assert cfg.wal_dir == "/data/test-wal"
    assert cfg.splunk_hec_url == "https://splunk.example.com:8088"
    assert cfg.splunk_hec_token == "test-token-123"
    assert cfg.file_output_dir == "/data/test-output"


def test_config_defaults() -> None:
    """Config defaults are suitable for the main entrypoint."""
    cfg = Config()
    assert cfg.http_port == 8080
    assert cfg.mode == "full"
    assert cfg.destinations == ["splunk_hec"]
