"""Tests for router partial success handling."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from shrike.destinations.base import Destination, HealthStatus, SendResult
from shrike.destinations.router import DestinationRouter
from shrike.destinations.wal import WriteAheadLog


class MockDestination(Destination):
    """Mock destination for testing partial success scenarios."""

    def __init__(self, name: str, send_result: SendResult, wal_append_result: int = 1) -> None:
        self._name = name
        self._send_result = send_result
        self._wal_append_result = wal_append_result
        self._wal = MagicMock(spec=WriteAheadLog)
        # Configure wal.append to return an actual int, not a MagicMock
        self._wal.append = AsyncMock(return_value=wal_append_result)

    @property
    def name(self) -> str:
        return self._name

    @property
    def wal(self) -> WriteAheadLog:
        return self._wal

    async def send_batch(self, events: list[dict]) -> SendResult:
        return self._send_result

    async def health(self) -> HealthStatus:
        return HealthStatus(healthy=True, pending=0, disk_usage_mb=0.0)

    async def close(self) -> None:
        pass


async def test_router_partial_success() -> None:
    """Router must return partial success when some destinations accept events.

    Mocks two destinations: one WAL full (0 accepted), one success (1 accepted).
    Verifies router.route() returns accepted=1 (partial success).
    """
    dest_full = MockDestination(
        "wal_full",
        SendResult(accepted=0, rejected=0, retryable=0, errors=["WAL at capacity"]),
        wal_append_result=0,
    )
    dest_success = MockDestination(
        "file_jsonl",
        SendResult(accepted=1, rejected=0, retryable=0),
        wal_append_result=1,
    )

    router = DestinationRouter([dest_full, dest_success])

    events = [{"class_uid": 1, "message": "test"}]
    results = await router.route(events)

    # Total accepted should be 1 (partial success)
    total_accepted = sum(r.accepted for r in results.values())
    assert total_accepted == 1, f"Expected accepted=1, got {total_accepted}"

    # WAL-full destination should have 0 accepted
    assert results["wal_full"].accepted == 0
    assert "WAL at capacity" in results["wal_full"].errors[0]

    # Successful destination should have 1 accepted
    assert results["file_jsonl"].accepted == 1