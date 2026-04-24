"""Destination worker — drains a WAL into its destination with exponential backoff."""

from __future__ import annotations

import asyncio

from shrike.destinations.base import Destination
from shrike.destinations.wal import WriteAheadLog
import structlog

logger = structlog.get_logger(__name__)


class DestinationWorker:
    """Background loop that reads unsent events from a WAL and delivers them.

    On retryable failures the worker backs off exponentially.
    Rejected (bad) events are advanced past — they never retry.
    """

    def __init__(
        self,
        destination: Destination,
        wal: WriteAheadLog | None = None,
        *,
        batch_size: int = 100,
        poll_interval: float = 1.0,
        base_retry_delay: float = 1.0,
        max_retry_delay: float = 300.0,
    ) -> None:
        self._dest = destination
        self._wal = wal if wal is not None else destination.wal
        self._batch_size = batch_size
        self._poll_interval = poll_interval
        self._base_retry_delay = base_retry_delay
        self._max_retry_delay = max_retry_delay
        self._running = False
        self._consecutive_failures = 0

    def stop(self) -> None:
        """Signal the run loop to exit after the current iteration."""
        self._running = False

    async def run(self) -> None:
        """Main loop: read unsent events, send batch, advance cursor."""
        self._running = True
        while self._running:
            events = await self._wal.read_unsent(batch_size=self._batch_size)
            if not events:
                await asyncio.sleep(self._poll_interval)
                continue

            result = await self._dest.send_batch(events)

            # Advance cursor past accepted + rejected (rejected are bad data, don't retry)
            advance_count = result.accepted + result.rejected
            if advance_count > 0:
                await self._wal.advance_cursor(advance_count)
                # D-2: compact WAL after each successful delivery to reclaim disk
                await self._wal.compact()

            if result.retryable > 0:
                self._consecutive_failures += 1
                delay = min(
                    self._base_retry_delay * (2 ** (self._consecutive_failures - 1)),
                    self._max_retry_delay,
                )
                logger.warning(
                    "Destination retryable events",
                    dest=self._dest.name,
                    retryable=result.retryable,
                    delay=delay,
                    attempt=self._consecutive_failures,
                    errors="; ".join(result.errors[:3]),
                )
                await asyncio.sleep(delay)
            else:
                self._consecutive_failures = 0
