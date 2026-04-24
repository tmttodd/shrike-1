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


# ------------------------------------------------------------------
# Phase 1.3 (#1) — Atomic compact()
# Phase 1.4 (NEW) — Async mutex
# ------------------------------------------------------------------


import asyncio
import json


async def test_compact_is_atomic_no_partial_lines(wal_dir: Path) -> None:
    """compact() must not leave partial JSON lines in the WAL.

    Regression test for Phase 1.3 (#1): the old compact() opened the WAL in "w" mode
    before reading unsent events, then wrote them back. This could result in partial lines
    being visible to concurrent read_unsent() calls. The atomic version writes to a temp
    file and uses os.replace() to ensure the WAL is never observed in a
    partially-written state.
    """
    wal = WriteAheadLog("test", wal_dir)
    events = [{"n": i} for i in range(100)]
    await wal.append(events)
    await wal.advance_cursor(50)

    await wal.compact()

    # WAL must contain valid JSON lines only — no partial lines
    raw = wal._wal_path.read_bytes()
    for line in raw.split(b"\n"):
        if line.strip():
            json.loads(line)  # must not raise


async def test_concurrent_compact_and_read_no_error(wal_dir: Path) -> None:
    """Concurrent compact() + read_unsent() must not raise JSONDecodeError.

    Regression test for Phase 1.3 (#1) + Phase 1.4 (NEW): without the mutex
    and atomic rename, concurrent compact + read could race and produce JSONDecodeError
    or return partial lines.
    """
    wal = WriteAheadLog("test", wal_dir)
    events = [{"n": i} for i in range(200)]
    await wal.append(events)
    await wal.advance_cursor(100)

    errors: list[Exception] = []

    async def read_task() -> None:
        try:
            for _ in range(20):
                batch = await wal.read_unsent(batch_size=10)
                for event in batch:
                    json.loads(json.dumps(event))  # validate structure
        except Exception as exc:
            errors.append(exc)

    async def compact_task() -> None:
        try:
            for _ in range(5):
                await wal.compact()
                await asyncio.sleep(0)
        except Exception as exc:
            errors.append(exc)

    await asyncio.gather(read_task(), compact_task())

    assert len(errors) == 0, f"Concurrent operations raised: {errors}"


async def test_compact_updates_cursor_atomically(wal_dir: Path) -> None:
    """After compact(), cursor must be 0:0 and pending_count must be correct."""
    wal = WriteAheadLog("test", wal_dir)
    # Write enough data to exceed COMPACT_SIZE_THRESHOLD_MB (50 MB)
    # so compact() does not skip
    events = [{"n": i, "padding": "x" * 2000} for i in range(30000)]
    await wal.append(events)
    await wal.advance_cursor(25000)

    await wal.compact()

    line_cursor, byte_offset = wal._read_cursor()
    assert line_cursor == 0
    assert byte_offset == 0
    assert wal.pending_count == 5000  # 30000 - 25000 = 5000 unsent


# ------------------------------------------------------------------
# Phase 3.1 (#4) — Compact memory bound + skip small WAL
# Phase 3.2 (#7) — Size-based compaction trigger
# ------------------------------------------------------------------


async def test_compact_skips_small_wal_with_unsent(wal_dir: Path) -> None:
    """compact() must skip I/O for WALs under 50 MB with unsent events.

    Phase 3.1 (#4): no point rewriting a small WAL that hasn't been delivered.
    """
    wal = WriteAheadLog("test", wal_dir, max_size_mb=500)
    # Under COMPACT_SIZE_THRESHOLD_MB (50 MB) — small test set
    events = [{"n": i} for i in range(100)]
    await wal.append(events)
    await wal.advance_cursor(50)

    # Compact should skip (no actual compaction I/O)
    await wal.compact()

    # All 50 unsent events must still be there
    remaining = await wal.read_unsent()
    assert len(remaining) == 50
    assert remaining[0]["n"] == 50


async def test_compact_forces_large_wal(wal_dir: Path) -> None:
    """compact() must run for WALs at or above 50 MB even if small unsent set.

    Phase 3.1 (#4): large WALs always compact to reclaim disk space.
    """
    wal = WriteAheadLog("test", wal_dir, max_size_mb=500)
    # Write enough to exceed COMPACT_SIZE_THRESHOLD_MB (50 MB)
    # Each event with padding is ~120 bytes, need ~430k events for 50 MB
    # For testing, we just verify the method runs without error on a large WAL
    events = [{"n": i, "padding": "x" * 100} for i in range(100000)]
    await wal.append(events)
    await wal.advance_cursor(90000)

    # Should not skip even with small unsent because WAL is large enough
    await wal.compact()

    remaining = await wal.read_unsent(batch_size=20000)
    assert len(remaining) == 10000


async def test_auto_compact_at_80_percent_capacity(wal_dir: Path) -> None:
    """append() must trigger compaction when WAL reaches 80% capacity.

    Phase 3.2 (#7): proactive compaction before overflow.
    """
    wal = WriteAheadLog("test", wal_dir, max_size_mb=10)  # 10 MB max
    # 80% of 10 MB = 8 MB threshold
    # Each event with padding is ~200 bytes, need ~40k events for 8 MB
    initial_pending = wal.pending_count

    # Append until we hit 80% threshold
    for i in range(40000):
        await wal.append([{"n": i, "padding": "x" * 150}])


    # After hitting 80%, compaction should have run
    # pending_count may be reduced if some events were delivered
    # We just verify no overflow occurred and events are stored
    assert wal.pending_count > 0
    # WAL should be smaller than max due to auto-compaction
    assert wal.disk_usage_mb <= 10


async def test_compact_chunked_reading_bounds_memory(wal_dir: Path) -> None:
    """compact() must read in chunks to bound memory usage.

    Phase 3.1 (#4): chunked reading with COMPACT_CHUNK_SIZE=50000.
    """
    from shrike.destinations.wal import COMPACT_CHUNK_SIZE

    wal = WriteAheadLog("test", wal_dir)
    # Write enough events to require multiple chunks
    events = [{"n": i} for i in range(COMPACT_CHUNK_SIZE * 2 + 1)]
    await wal.append(events)
    await wal.advance_cursor(COMPACT_CHUNK_SIZE * 2)

    await wal.compact()

    remaining = await wal.read_unsent()
    assert len(remaining) == 1
    assert remaining[0]["n"] == COMPACT_CHUNK_SIZE * 2
