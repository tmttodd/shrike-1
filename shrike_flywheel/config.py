"""Shrike-specific config loader."""

from pathlib import Path

from flywheel.config import FlywheelConfig


def load_config(config_path: str | None = None) -> FlywheelConfig:
    """Load Shrike flywheel config.

    Args:
        config_path: Path to config.yaml (default: this directory)

    Returns:
        FlywheelConfig instance
    """
    if config_path is None:
        config_path = str(Path(__file__).parent / "config.yaml")

    return FlywheelConfig.from_yaml(config_path)