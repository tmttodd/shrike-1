"""File/JSONL destination — writes OCSF events to category-partitioned JSONL files."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

import aiofiles

from shrike.destinations.base import Destination, HealthStatus, SendResult
from shrike.destinations.wal import WriteAheadLog

# OCSF category_uid → directory name
_CATEGORY_MAP: dict[int, str] = {
    1: "system_activity",
    2: "findings",
    3: "iam",
    4: "network_activity",
    5: "discovery",
    6: "application_activity",
}


def _category_dir(uid: int | None) -> str:
    """Map an OCSF category_uid to a human-readable directory name.

    ``None`` or unrecognised values map to ``raw``.
    """
    if uid is None:
        return "raw"
    return _CATEGORY_MAP.get(uid, "raw")


class FileJSONLDestination(Destination):
    """Write OCSF events to local JSONL files partitioned by category."""

    name = "file_jsonl"

    def __init__(
        self,
        output_dir: str,
        wal_dir: str | None = None,
        max_size_mb: int = 500,
        **kwargs: object,
    ) -> None:
        self._output = Path(output_dir)
        self._output.mkdir(parents=True, exist_ok=True)

        wal_path = Path(wal_dir) if wal_dir else self._output / ".wal"
        self.wal = WriteAheadLog(self.name, wal_path, max_size_mb=max_size_mb)

    async def send_batch(self, events: list[dict]) -> SendResult:
        """Group events by category and write one JSONL file per category."""
        if not events:
            return SendResult(accepted=0, rejected=0, retryable=0)

        # Group by category directory
        by_category: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            cat = _category_dir(event.get("category_uid"))
            by_category[cat].append(event)

        accepted = 0
        errors: list[str] = []
        ts = str(int(time.time() * 1_000_000))  # microsecond timestamp for uniqueness

        for category_name, cat_events in by_category.items():
            cat_dir = self._output / category_name
            cat_dir.mkdir(parents=True, exist_ok=True)
            out_path = cat_dir / f"{ts}.jsonl"

            try:
                lines = "".join(json.dumps(e) + "\n" for e in cat_events)
                async with aiofiles.open(out_path, "w") as f:
                    await f.write(lines)
                accepted += len(cat_events)
            except OSError as exc:
                errors.append(f"{category_name}: {exc}")

        rejected = len(events) - accepted
        return SendResult(accepted=accepted, rejected=rejected, retryable=0, errors=errors)

    async def health(self) -> HealthStatus:
        """Always healthy — local filesystem destination."""
        return HealthStatus(
            healthy=True,
            pending=self.wal.pending_count,
            disk_usage_mb=self.wal.disk_usage_mb,
        )

    async def close(self) -> None:
        """No-op — nothing to tear down for file writes."""
