"""Tests for OTel Collector subprocess manager."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from shrike.collector.manager import CollectorManager
from shrike.config import Config


@pytest.fixture
def manager(tmp_path: str) -> CollectorManager:
    config = Config(mode="full")
    return CollectorManager(config, config_dir=str(tmp_path))


async def test_generates_config_on_start(tmp_path: str) -> None:
    """start() writes otel-config.yaml with filelog/docker content."""
    config = Config(mode="full")
    mgr = CollectorManager(config, config_dir=str(tmp_path))

    fake_process = AsyncMock()
    fake_process.pid = 12345
    fake_process.returncode = None
    fake_process.wait = AsyncMock(side_effect=lambda: None)

    with (
        patch("shrike.collector.manager.shutil.which", return_value="/usr/bin/otelcol-contrib"),
        patch(
            "shrike.collector.manager.asyncio.create_subprocess_exec",
            return_value=fake_process,
        ),
    ):
        await mgr.start()

    config_path = os.path.join(str(tmp_path), "otel-config.yaml")
    assert os.path.isfile(config_path)

    content = open(config_path).read()
    assert "filelog/docker" in content
    assert "/var/lib/docker/containers" in content

    # Cleanup
    await mgr.stop()


async def test_raises_if_binary_not_found(tmp_path: str) -> None:
    """start() raises FileNotFoundError when otelcol-contrib is missing."""
    config = Config(mode="full")
    mgr = CollectorManager(config, config_dir=str(tmp_path))

    with patch("shrike.collector.manager.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="otelcol-contrib"):
            await mgr.start()


async def test_is_running_property(tmp_path: str) -> None:
    """is_running reflects subprocess state."""
    config = Config(mode="full")
    mgr = CollectorManager(config, config_dir=str(tmp_path))

    assert mgr.is_running is False

    fake_process = AsyncMock()
    fake_process.pid = 99
    fake_process.returncode = None
    fake_process.wait = AsyncMock(side_effect=lambda: None)

    with (
        patch("shrike.collector.manager.shutil.which", return_value="/usr/bin/otelcol-contrib"),
        patch(
            "shrike.collector.manager.asyncio.create_subprocess_exec",
            return_value=fake_process,
        ),
    ):
        await mgr.start()
        assert mgr.is_running is True

    await mgr.stop()


async def test_forwarder_config_on_start(tmp_path: str) -> None:
    """Forwarder mode config is written correctly."""
    config = Config(mode="forwarder", forward_to="upstream:4317")
    mgr = CollectorManager(config, config_dir=str(tmp_path))

    fake_process = AsyncMock()
    fake_process.pid = 100
    fake_process.returncode = None
    fake_process.wait = AsyncMock(side_effect=lambda: None)

    with (
        patch("shrike.collector.manager.shutil.which", return_value="/usr/bin/otelcol-contrib"),
        patch(
            "shrike.collector.manager.asyncio.create_subprocess_exec",
            return_value=fake_process,
        ),
    ):
        await mgr.start()

    config_path = os.path.join(str(tmp_path), "otel-config.yaml")
    content = open(config_path).read()
    assert "filelog/docker" in content
    assert "upstream:4317" in content
    assert "syslog" not in content

    await mgr.stop()
