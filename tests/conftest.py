"""Shared pytest fixtures for Shrike tests."""

import pytest

from shrike.config import Config


@pytest.fixture
def config() -> Config:
    """Provide a test configuration with safe defaults."""
    return Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir="/tmp/shrike-test-wal",
        file_output_dir="/tmp/shrike-test-output",
    )
