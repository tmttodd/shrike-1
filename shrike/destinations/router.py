"""Fan-out router — appends events to every destination's WAL independently."""

from __future__ import annotations

from shrike.destinations.base import Destination, SendResult
from shrike.destinations.wal import WriteAheadLog


class DestinationRouter:
    """Routes incoming events to all registered destinations.

    Each destination gets its own WAL so a failure in one does not block
    the others.
    """

    def __init__(self, destinations: list[Destination]) -> None:
        self._destinations = destinations

    async def route(self, events: list[dict]) -> dict[str, SendResult]:
        """Append *events* to each destination's WAL.

        Returns a mapping of destination name -> SendResult.  If a WAL
        overflows (returns 0), that destination gets ``accepted=0`` while
        the others are unaffected.
        """
        results: dict[str, SendResult] = {}
        for dest in self._destinations:
            wal: WriteAheadLog = dest.wal
            written = await wal.append(events)
            if written == 0:
                results[dest.name] = SendResult(
                    accepted=0,
                    rejected=len(events),
                    retryable=0,
                    errors=["WAL overflow — events dropped"],
                )
            else:
                results[dest.name] = SendResult(
                    accepted=written,
                    rejected=0,
                    retryable=0,
                )
        return results
