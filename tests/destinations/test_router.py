"""Tests for the DestinationRouter fan-out."""

from __future__ import annotations

from pathlib import Path

import pytest

from shrike.destinations.base import Destination, HealthStatus, SendResult
from shrike.destinations.router import DestinationRouter
from shrike.destinations.wal import WriteAheadLog


class FakeDestination(Destination):
    """Minimal concrete destination backed by a real WAL for testing."""

    def __init__(self, name: str, wal: WriteAheadLog) -> None:
        self.name = name
        self.wal = wal

    async def send_batch(self, events: list[dict]) -> SendResult:
        return SendResult(accepted=len(events), rejected=0, retryable=0)

    async def health(self) -> HealthStatus:
        return HealthStatus(
            healthy=True,
            pending=self.wal.pending_count,
            disk_usage_mb=self.wal.disk_usage_mb,
        )

    async def close(self) -> None:
        pass


@pytest.fixture
def wal_dir(tmp_path: Path) -> Path:
    return tmp_path / "wal"


async def test_router_appends_to_all_wals(wal_dir: Path) -> None:
    wal_a = WriteAheadLog("dest_a", wal_dir)
    wal_b = WriteAheadLog("dest_b", wal_dir)
    dest_a = FakeDestination("dest_a", wal_a)
    dest_b = FakeDestination("dest_b", wal_b)

    router = DestinationRouter([dest_a, dest_b])
    results = await router.route([{"event": 1}])

    assert results["dest_a"].accepted == 1
    assert results["dest_b"].accepted == 1

    assert len(await wal_a.read_unsent()) == 1
    assert len(await wal_b.read_unsent()) == 1


async def test_router_independent_failure(wal_dir: Path) -> None:
    wal_overflow = WriteAheadLog("overflow", wal_dir, max_size_mb=0)
    wal_ok = WriteAheadLog("ok", wal_dir)
    dest_overflow = FakeDestination("overflow", wal_overflow)
    dest_ok = FakeDestination("ok", wal_ok)

    router = DestinationRouter([dest_overflow, dest_ok])
    results = await router.route([{"event": 1}])

    assert results["overflow"].accepted == 0
    assert results["overflow"].rejected == 1
    assert results["ok"].accepted == 1

    assert len(await wal_ok.read_unsent()) == 1
