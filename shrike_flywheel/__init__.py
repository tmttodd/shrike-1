"""Shrike flywheel — Shrike-specific flywheel layer.

Provides Shrike-specific detectors and configuration. Inherits from
the generic flywheel framework and adds Shrike-specific logic:
- WAL file detection
- Structured log detection
- Splunk metric detection
- Docker inspect for OOM/restart
"""

from shrike_flywheel.config import load_config

__all__ = ["load_config"]