"""Flywheel state management."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import structlog

logger = structlog.get_logger("flywheel.state")

# Default state file location
DEFAULT_STATE_FILE = "/data/flywheel_state.json"


@dataclass
class FlywheelState:
    """Persistent state for the flywheel system.

    Tracks:
    - Total events processed
    - Issues created by component
    - 7-day rolling error rate
    - Stability status (STABLE when <1% error rate for 7 consecutive days)
    """

    total_events_processed: int = 0
    total_issues_created: int = 0
    issues_by_component: dict[str, int] = field(default_factory=dict)
    error_rate_7day: float = 0.0
    stability_status: str = "INITIALIZING"
    consecutive_stable_days: int = 0
    last_cycle_time: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlywheelState":
        """Create from dictionary."""
        return cls(
            total_events_processed=data.get("total_events_processed", 0),
            total_issues_created=data.get("total_issues_created", 0),
            issues_by_component=data.get("issues_by_component", {}),
            error_rate_7day=data.get("error_rate_7day", 0.0),
            stability_status=data.get("stability_status", "INITIALIZING"),
            consecutive_stable_days=data.get("consecutive_stable_days", 0),
            last_cycle_time=data.get("last_cycle_time", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


def load_state(state_file: str = DEFAULT_STATE_FILE) -> FlywheelState:
    """Load flywheel state from file.

    Args:
        state_file: Path to state file

    Returns:
        FlywheelState instance (new if file doesn't exist).
    """
    path = Path(state_file)

    if not path.is_file():
        logger.info("No existing state file, creating new state")
        return FlywheelState()

    try:
        with open(path, "r") as f:
            data = json.load(f)
        logger.debug("Loaded state", path=str(path), events=data.get("total_events_processed", 0))
        return FlywheelState.from_dict(data)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load state, creating new", path=str(path), error=str(e))
        return FlywheelState()


def save_state(state: FlywheelState, state_file: str = DEFAULT_STATE_FILE) -> None:
    """Save flywheel state to file.

    Args:
        state: FlywheelState to save
        state_file: Path to state file
    """
    path = Path(state_file)
    state.updated_at = datetime.utcnow().isoformat() + "Z"

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)
        logger.debug("Saved state", path=str(path), events=state.total_events_processed)
    except OSError as e:
        logger.error("Failed to save state", path=str(path), error=str(e))