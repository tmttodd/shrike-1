"""Tests for the Write-Ahead Log."""

from __future__ import annotations

from pathlib import Path

import pytest

from shrike.destinations.wal import WriteAheadLog


@pytest.fixture
def wal_dir(tmp_path: Path) -> Path:
    return tmp_path / "wal"


async def test_append_and_read(wal_dir: Path) -> None:
    wal = WriteAheadLog("test", wal_dir)
    event = {"class_uid": 1, "message": "hello"}

    written = await wal.append([event])
    assert written == 1

    events = await wal.read_unsent()
    assert len(events) == 1
    assert events[0]["message"] == "hello"


async def test_cursor_advances(wal_dir: Path) -> None:
    wal = WriteAheadLog("test", wal_dir)
    await wal.append([{"i": 0}, {"i": 1}, {"i": 2}])

    batch1 = await wal.read_unsent(batch_size=2)
    assert len(batch1) == 2
    await wal.advance_cursor(2)

    batch2 = await wal.read_unsent()
    assert len(batch2) == 1
    assert batch2[0]["i"] == 2


async def test_crash_recovery(wal_dir: Path) -> None:
    wal1 = WriteAheadLog("test", wal_dir)
    await wal1.append([{"a": 1}, {"a": 2}])
    await wal1.advance_cursor(1)

    # Simulate crash: create a NEW instance pointing at the same path
    wal2 = WriteAheadLog("test", wal_dir)
    unsent = await wal2.read_unsent()
    assert len(unsent) == 1
    assert unsent[0]["a"] == 2


async def test_compact(wal_dir: Path) -> None:
    wal = WriteAheadLog("test", wal_dir)
    events = [{"n": i} for i in range(100)]
    await wal.append(events)
    await wal.advance_cursor(90)

    await wal.compact()

    remaining = await wal.read_unsent()
    assert len(remaining) == 10
    assert remaining[0]["n"] == 90
    assert wal.pending_count == 10


async def test_pending_count(wal_dir: Path) -> None:
    wal = WriteAheadLog("test", wal_dir)
    assert wal.pending_count == 0

    await wal.append([{"x": 1}, {"x": 2}, {"x": 3}])
    assert wal.pending_count == 3

    await wal.advance_cursor(2)
    assert wal.pending_count == 1


async def test_overflow_drops(wal_dir: Path) -> None:
    wal = WriteAheadLog("test", wal_dir, max_size_mb=0)
    result = await wal.append([{"big": "event"}])
    assert result == 0
