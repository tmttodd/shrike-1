"""Destination abstractions — SendResult, HealthStatus, and the Destination ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shrike.destinations.wal import WriteAheadLog


@dataclass
class SendResult:
    """Outcome of a batch send attempt."""

    accepted: int
    rejected: int
    retryable: int
    errors: list[str] = field(default_factory=list)


@dataclass
class HealthStatus:
    """Point-in-time health snapshot for a destination."""

    healthy: bool
    pending: int
    disk_usage_mb: float
    last_send_epoch: float = 0.0
    retry_count: int = 0
    error: str = ""


class Destination(ABC):
    """Abstract base for all fan-out destinations.

    Concrete subclasses must set ``name`` and ``wal``, and implement
    ``send_batch``, ``health``, and ``close``.
    """

    name: str
    wal: WriteAheadLog

    @abstractmethod
    async def send_batch(self, events: list[dict]) -> SendResult:
        """Send a batch of OCSF events. Returns outcome."""

    @abstractmethod
    async def health(self) -> HealthStatus:
        """Return current health snapshot."""

    @abstractmethod
    async def close(self) -> None:
        """Release resources (flush WAL, close connections, etc.)."""
