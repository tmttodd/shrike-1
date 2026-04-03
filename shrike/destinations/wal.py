"""Write-Ahead Log — append-only JSONL with cursor tracking and compaction."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiofiles

logger = logging.getLogger(__name__)


class WriteAheadLog:
    """Durable WAL backed by a JSONL file with a cursor for delivery tracking.

    Each destination gets its own WAL so failures are isolated.

    The cursor tracks both line count and byte offset so that ``read_unsent``
    can seek directly to the undelivered region — O(batch_size) instead of
    O(total_lines).
    """

    def __init__(self, dest_name: str, wal_dir: Path | str, max_size_mb: int = 500) -> None:
        self._dir = Path(wal_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._wal_path = self._dir / f"{dest_name}.wal.jsonl"
        self._cursor_path = self._dir / f"{dest_name}.cursor"
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._dest_name = dest_name

        # Ensure files exist
        if not self._wal_path.exists():
            self._wal_path.touch()
        if not self._cursor_path.exists():
            self._cursor_path.write_text("0:0")

        # D-4: In-memory line counter (count from file once at startup for crash recovery)
        self._line_count = self._count_lines_sync()

        # Recover byte offset from cursor file, or rebuild it
        line_cursor, byte_offset = self._read_cursor()
        if byte_offset == 0 and line_cursor > 0:
            # Legacy cursor without byte offset — rebuild by scanning
            byte_offset = self._compute_byte_offset(line_cursor)
            self._write_cursor_sync(line_cursor, byte_offset)

    async def append(self, events: list[dict]) -> int:
        """Append events as JSONL lines. Returns count appended, 0 if overflow."""
        if self._wal_path.stat().st_size >= self._max_size_bytes:
            logger.error(
                "WAL overflow for %s: dropping %d events (max %d MB)",
                self._dest_name,
                len(events),
                self._max_size_bytes // (1024 * 1024),
            )
            return 0

        lines = "".join(json.dumps(e) + "\n" for e in events)
        async with aiofiles.open(self._wal_path, "a") as f:
            await f.write(lines)
        self._line_count += len(events)
        return len(events)

    async def read_unsent(self, batch_size: int = 100) -> list[dict]:
        """Read up to batch_size events starting from the current cursor.

        Uses byte offset to seek directly to the undelivered region,
        avoiding an O(total_lines) scan from the start of the file.
        """
        _line_cursor, byte_offset = self._read_cursor()
        events: list[dict] = []
        async with aiofiles.open(self._wal_path, "rb") as f:
            await f.seek(byte_offset)
            while len(events) < batch_size:
                raw_line = await f.readline()
                if not raw_line:
                    break
                stripped = raw_line.strip()
                if stripped:
                    events.append(json.loads(stripped))
        return events

    async def advance_cursor(self, count: int) -> None:
        """Move the cursor forward by *count* events.

        Reads through *count* lines from the current byte offset to compute
        the new byte offset, keeping subsequent reads O(batch_size).
        """
        line_cursor, byte_offset = self._read_cursor()
        new_line_cursor = line_cursor + count

        # Compute new byte offset by reading forward through the lines we are advancing past
        new_byte_offset = byte_offset
        async with aiofiles.open(self._wal_path, "rb") as f:
            await f.seek(byte_offset)
            advanced = 0
            while advanced < count:
                raw_line = await f.readline()
                if not raw_line:
                    break
                new_byte_offset += len(raw_line)
                if raw_line.strip():
                    advanced += 1

        async with aiofiles.open(self._cursor_path, "w") as f:
            await f.write(f"{new_line_cursor}:{new_byte_offset}")

    async def compact(self) -> None:
        """Rewrite WAL without already-delivered events, reset cursor to 0."""
        unsent = await self.read_unsent(batch_size=2**31)
        async with aiofiles.open(self._wal_path, "w") as f:
            for event in unsent:
                await f.write(json.dumps(event) + "\n")
        async with aiofiles.open(self._cursor_path, "w") as f:
            await f.write("0:0")
        self._line_count = len(unsent)

    @property
    def pending_count(self) -> int:
        """Number of events not yet delivered."""
        line_cursor, _ = self._read_cursor()
        return self._line_count - line_cursor

    @property
    def disk_usage_mb(self) -> float:
        """WAL file size in megabytes."""
        if not self._wal_path.exists():
            return 0.0
        return self._wal_path.stat().st_size / (1024 * 1024)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_cursor(self) -> tuple[int, int]:
        """Read cursor as (line_count, byte_offset) tuple."""
        try:
            raw = self._cursor_path.read_text().strip()
            if ":" in raw:
                parts = raw.split(":", 1)
                return int(parts[0]), int(parts[1])
            # Legacy format: line count only, byte offset = 0
            return int(raw), 0
        except (FileNotFoundError, ValueError):
            return 0, 0

    def _write_cursor_sync(self, line_cursor: int, byte_offset: int) -> None:
        """Write cursor synchronously (used only during startup recovery)."""
        self._cursor_path.write_text(f"{line_cursor}:{byte_offset}")

    def _compute_byte_offset(self, line_count: int) -> int:
        """Compute byte offset for a given line count by scanning from start."""
        if not self._wal_path.exists() or line_count == 0:
            return 0
        offset = 0
        lines_seen = 0
        with open(self._wal_path, "rb") as f:
            for raw_line in f:
                if lines_seen >= line_count:
                    break
                offset += len(raw_line)
                if raw_line.strip():
                    lines_seen += 1
        return offset

    def _count_lines_sync(self) -> int:
        """Count non-empty lines in WAL file. Called once at startup for crash recovery."""
        if not self._wal_path.exists():
            return 0
        with open(self._wal_path) as f:
            return sum(1 for line in f if line.strip())
