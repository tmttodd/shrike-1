"""Tests for the destination worker (WAL drainer)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from shrike.destinations.base import Destination, HealthStatus, SendResult
from shrike.destinations.wal import WriteAheadLog
from shrike.destinations.worker import DestinationWorker


class CountingDestination(Destination):
    """Fake destination that counts batches and can simulate failures."""

    name = "counting"

    def __init__(self) -> None:
        self.batches_sent: list[list[dict]] = []
        self.fail_next: int = 0

    async def send_batch(self, events: list[dict]) -> SendResult:
        if self.fail_next > 0:
            self.fail_next -= 1
            return SendResult(accepted=0, rejected=0, retryable=len(events), errors=["transient"])
        self.batches_sent.append(list(events))
        return SendResult(accepted=len(events), rejected=0, retryable=0)

    async def health(self) -> HealthStatus:
        return HealthStatus(healthy=True, pending=0, disk_usage_mb=0.0)

    async def close(self) -> None:
        pass


@pytest.fixture
def wal_dir(tmp_path: Path) -> Path:
    return tmp_path / "wal"


async def test_worker_drains_wal(wal_dir: Path) -> None:
    """Append 2 events, run worker briefly, verify both sent and WAL drained."""
    wal = WriteAheadLog("counting", wal_dir)
    dest = CountingDestination()
    worker = DestinationWorker(dest, wal, batch_size=10, poll_interval=0.01)

    await wal.append([{"class_uid": 1, "msg": "a"}, {"class_uid": 1, "msg": "b"}])
    assert wal.pending_count == 2

    task = asyncio.create_task(worker.run())
    # Give the worker a moment to drain
    await asyncio.sleep(0.1)
    worker.stop()
    await task

    assert wal.pending_count == 0
    total_events = sum(len(b) for b in dest.batches_sent)
    assert total_events == 2


async def test_worker_retries_on_failure(wal_dir: Path) -> None:
    """Fail 2 times, then verify worker eventually succeeds."""
    wal = WriteAheadLog("counting", wal_dir)
    dest = CountingDestination()
    dest.fail_next = 2
    worker = DestinationWorker(
        dest, wal, batch_size=10, poll_interval=0.01, base_retry_delay=0.01, max_retry_delay=0.05
    )

    await wal.append([{"class_uid": 1, "msg": "retry_me"}])

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.3)
    worker.stop()
    await task

    assert wal.pending_count == 0
    assert len(dest.batches_sent) == 1
    assert dest.batches_sent[0][0]["msg"] == "retry_me"


async def test_worker_advances_past_rejected(wal_dir: Path) -> None:
    """Rejected events are skipped (advanced past), never retried."""

    class RejectingDestination(Destination):
        name = "rejector"

        async def send_batch(self, events: list[dict]) -> SendResult:
            return SendResult(accepted=0, rejected=len(events), retryable=0, errors=["bad data"])

        async def health(self) -> HealthStatus:
            return HealthStatus(healthy=True, pending=0, disk_usage_mb=0.0)

        async def close(self) -> None:
            pass

    wal = WriteAheadLog("rejector", wal_dir)
    dest = RejectingDestination()
    worker = DestinationWorker(dest, wal, batch_size=10, poll_interval=0.01)

    await wal.append([{"bad": True}])
    assert wal.pending_count == 1

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.1)
    worker.stop()
    await task

    assert wal.pending_count == 0
