"""Tests for OTel Collector config generation."""

from __future__ import annotations

import yaml

from shrike.collector.config_gen import generate_otel_config
from shrike.config import Config


def test_full_mode_has_all_receivers() -> None:
    """Full mode must include filelog, syslog, and otlp receivers."""
    config = Config(mode="full")
    result = yaml.safe_load(generate_otel_config(config))

    receivers = result["receivers"]
    assert "filelog/docker" in receivers
    assert "syslog" in receivers
    assert "otlp" in receivers


def test_forwarder_mode_only_filelog() -> None:
    """Forwarder mode has filelog but NOT syslog; exports via otlp."""
    config = Config(mode="forwarder", forward_to="upstream:4317")
    result = yaml.safe_load(generate_otel_config(config))

    receivers = result["receivers"]
    assert "filelog/docker" in receivers
    assert "syslog" not in receivers

    exporters = result["exporters"]
    assert "otlp" in exporters
    assert "otlphttp/shrike" not in exporters


def test_custom_docker_log_path() -> None:
    """Custom docker log path appears in filelog include glob."""
    custom_path = "/var/log/custom-docker"
    config = Config(mode="full", docker_log_path=custom_path)
    raw = generate_otel_config(config)

    assert custom_path in raw

    result = yaml.safe_load(raw)
    include = result["receivers"]["filelog/docker"]["include"]
    assert include == [f"{custom_path}/*/*.log"]


def test_file_storage_extension() -> None:
    """file_storage extension is present in both modes."""
    for mode in ("full", "forwarder"):
        config = Config(mode=mode, forward_to="upstream:4317")
        result = yaml.safe_load(generate_otel_config(config))

        assert "file_storage" in result["extensions"]
        assert result["extensions"]["file_storage"]["directory"] == "/data/otel/buffer"

        # Also in service.extensions
        assert "file_storage" in result["service"]["extensions"]


def test_full_mode_three_pipelines() -> None:
    """Full mode produces exactly 3 pipelines."""
    config = Config(mode="full")
    result = yaml.safe_load(generate_otel_config(config))

    pipelines = result["service"]["pipelines"]
    assert "logs/docker" in pipelines
    assert "logs/syslog" in pipelines
    assert "logs/remote" in pipelines
    assert len(pipelines) == 3


def test_forwarder_mode_one_pipeline() -> None:
    """Forwarder mode produces exactly 1 pipeline."""
    config = Config(mode="forwarder", forward_to="upstream:4317")
    result = yaml.safe_load(generate_otel_config(config))

    pipelines = result["service"]["pipelines"]
    assert "logs" in pipelines
    assert len(pipelines) == 1


def test_forwarder_sending_queue_uses_file_storage() -> None:
    """Forwarder otlp exporter has a file-backed sending queue."""
    config = Config(mode="forwarder", forward_to="upstream:4317")
    result = yaml.safe_load(generate_otel_config(config))

    otlp = result["exporters"]["otlp"]
    assert otlp["sending_queue"]["enabled"] is True
    assert otlp["sending_queue"]["storage"] == "file_storage"


def test_full_mode_ports() -> None:
    """Full mode uses configured ports for syslog, otlp, and http."""
    config = Config(
        mode="full",
        syslog_port=1515,
        otlp_grpc_port=5317,
        otlp_http_port=5318,
        http_port=9090,
    )
    result = yaml.safe_load(generate_otel_config(config))

    assert "0.0.0.0:1515" in str(result["receivers"]["syslog"])
    assert result["receivers"]["otlp"]["protocols"]["grpc"]["endpoint"] == "0.0.0.0:5317"
    assert result["receivers"]["otlp"]["protocols"]["http"]["endpoint"] == "0.0.0.0:5318"
    assert result["exporters"]["otlphttp/shrike"]["endpoint"] == "http://localhost:9090"
