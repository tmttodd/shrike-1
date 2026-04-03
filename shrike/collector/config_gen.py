"""Generate OTel Collector configuration from Shrike Config."""

from __future__ import annotations

from typing import Any

import yaml

from shrike.config import Config


def generate_otel_config(config: Config) -> str:
    """Generate an OTel Collector YAML config string from a Shrike Config.

    In FULL mode: filelog + syslog + otlp receivers, otlphttp exporter to Shrike,
    three pipelines (docker, syslog, remote).

    In FORWARDER mode: filelog receiver only, otlp exporter to upstream with
    file-backed sending queue, one pipeline.
    """
    otel: dict[str, Any] = {}

    # --- Extensions (both modes) ---
    extensions: dict[str, Any] = {
        "file_storage": {
            "directory": "/data/otel/buffer",
            "create_directory": True,
        },
    }

    # S-2: Bearer token auth for OTLP receiver in full mode
    if config.mode == "full" and config.ingest_api_key:
        extensions["bearertokenauth"] = {
            "token": config.ingest_api_key,
        }

    otel["extensions"] = extensions

    # --- Receivers ---
    receivers: dict[str, Any] = {}

    # filelog/docker — both modes
    receivers["filelog/docker"] = {
        "include": [f"{config.docker_log_path}/*/*.log"],
        "operators": [
            {
                "type": "json_parser",
                "id": "json_parser",
            },
            {
                "type": "move",
                "id": "move_log",
                "from": "attributes.log",
                "to": "body",
            },
        ],
    }

    if config.mode == "full":
        # syslog receiver (TCP + UDP)
        receivers["syslog"] = {
            "tcp": {
                "listen_address": f"0.0.0.0:{config.syslog_port}",
            },
            "udp": {
                "listen_address": f"0.0.0.0:{config.syslog_port}",
            },
            "protocol": "rfc3164",
        }

        # otlp receiver (gRPC + HTTP)
        grpc_cfg: dict[str, Any] = {
            "endpoint": f"0.0.0.0:{config.otlp_grpc_port}",
        }
        http_cfg: dict[str, Any] = {
            "endpoint": f"0.0.0.0:{config.otlp_http_port}",
        }
        if config.ingest_api_key:
            grpc_cfg["auth"] = {"authenticator": "bearertokenauth"}
            http_cfg["auth"] = {"authenticator": "bearertokenauth"}
        receivers["otlp"] = {
            "protocols": {
                "grpc": grpc_cfg,
                "http": http_cfg,
            },
        }

    otel["receivers"] = receivers

    # --- Processors (both modes) ---
    otel["processors"] = {
        "batch": {
            "send_batch_size": 100,
            "timeout": "5s",
        },
    }

    # --- Exporters ---
    exporters: dict[str, Any] = {}

    if config.mode == "full":
        otlphttp_cfg: dict[str, Any] = {
            "endpoint": f"http://localhost:{config.http_port}",
            "encoding": "json",
        }
        if config.ingest_api_key:
            otlphttp_cfg["headers"] = {
                "authorization": f"Bearer {config.ingest_api_key}",
            }
        exporters["otlphttp/shrike"] = otlphttp_cfg
    else:
        # forwarder mode
        otlp_cfg: dict[str, Any] = {
            "endpoint": config.forward_to,
            "sending_queue": {
                "enabled": True,
                "storage": "file_storage",
            },
        }
        if config.forwarder_tls_insecure:
            otlp_cfg["tls"] = {"insecure": True}
        exporters["otlp"] = otlp_cfg

    otel["exporters"] = exporters

    # --- Service / Pipelines ---
    pipelines: dict[str, Any] = {}

    if config.mode == "full":
        pipelines["logs/docker"] = {
            "receivers": ["filelog/docker"],
            "processors": ["batch"],
            "exporters": ["otlphttp/shrike"],
        }
        pipelines["logs/syslog"] = {
            "receivers": ["syslog"],
            "processors": ["batch"],
            "exporters": ["otlphttp/shrike"],
        }
        pipelines["logs/remote"] = {
            "receivers": ["otlp"],
            "processors": ["batch"],
            "exporters": ["otlphttp/shrike"],
        }
    else:
        pipelines["logs"] = {
            "receivers": ["filelog/docker"],
            "processors": ["batch"],
            "exporters": ["otlp"],
        }

    service_extensions = ["file_storage"]
    if config.mode == "full" and config.ingest_api_key:
        service_extensions.append("bearertokenauth")

    otel["service"] = {
        "extensions": service_extensions,
        "pipelines": pipelines,
    }

    return yaml.dump(otel, default_flow_style=False, sort_keys=False)
