"""Flywheel state management — project-agnostic persistent state.

Tracks deployment phase, error rates, and stability metrics across
detection cycles. Works for any project — no project-specific fields.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger("flywheel.state")


@dataclass
class FlywheelState:
    """Persistent state for the flywheel system.

    Tracks:
    - Deployment phase (DEPLOYING → FIRST_RUN → RUNNING → STABLE)
    - Total detection cycles run
    - Issues created
    - 7-day rolling error rate
    - Consecutive stable days
    - Timestamps for phase transitions

    No project-specific fields — works for any project.
    """

    phase: str = "DEPLOYING"
    started_at: str = ""
    total_runs: int = 0
    issues_created: int = 0
    error_rate: float = 0.0
    consecutive_stable_days: int = 0

    # Phase timestamps
    deployment_started_at: str | None = None
    deployment_completed_at: str | None = None
    first_run_completed_at: str | None = None
    stable_achieved_at: str | None = None

    # Error tracking
    errors_by_component: dict[str, int] = field(default_factory=dict)
    total_errors: int = 0

    # Last update
    last_cycle_at: str | None = None
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.utcnow().isoformat() + "Z"
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlywheelState":
        """Create from dictionary."""
        return cls(
            phase=data.get("phase", "DEPLOYING"),
            started_at=data.get("started_at", ""),
            total_runs=data.get("total_runs", 0),
            issues_created=data.get("issues_created", 0),
            error_rate=data.get("error_rate", 0.0),
            consecutive_stable_days=data.get("consecutive_stable_days", 0),
            deployment_started_at=data.get("deployment_started_at"),
            deployment_completed_at=data.get("deployment_completed_at"),
            first_run_completed_at=data.get("first_run_completed_at"),
            stable_achieved_at=data.get("stable_achieved_at"),
            errors_by_component=data.get("errors_by_component", {}),
            total_errors=data.get("total_errors", 0),
            last_cycle_at=data.get("last_cycle_at"),
            updated_at=data.get("updated_at", ""),
        )

    def record_run(self) -> None:
        """Record a detection cycle run."""
        self.total_runs += 1
        self.last_cycle_at = datetime.utcnow().isoformat() + "Z"
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def record_issue(self, component: str, issue_number: int) -> None:
        """Record a GitHub issue created.

        Args:
            component: Component that triggered the issue
            issue_number: GitHub issue number
        """
        self.issues_created += 1
        self.total_errors += 1
        if component not in self.errors_by_component:
            self.errors_by_component[component] = 0
        self.errors_by_component[component] += 1
        self._recalculate_error_rate()
        self.updated_at = datetime.utcnow().isoformat() + "Z"

    def record_detection(self, component: str) -> None:
        """Record a detection (issue found, may not create GitHub issue).

        Args:
            component: Component that detected the issue
        """
        if component not in self.errors_by_component:
            self.errors_by_component[component] = 0
        self.errors_by_component[component] += 1
        self._recalculate_error_rate()

    def _recalculate_error_rate(self) -> None:
        """Recalculate rolling error rate."""
        total_detections = sum(self.errors_by_component.values())
        if total_detections > 0:
            self.error_rate = self.total_errors / max(total_detections, 1)

    def set_phase(self, phase: str) -> None:
        """Set deployment phase.

        Args:
            phase: New phase (DEPLOYING, FIRST_RUN, RUNNING, STABLE)
        """
        if self.phase != phase:
            old_phase = self.phase
            self.phase = phase
            timestamp = datetime.utcnow().isoformat() + "Z"

            if phase == "DEPLOYING":
                self.deployment_started_at = timestamp
            elif phase == "FIRST_RUN":
                self.deployment_completed_at = timestamp
            elif phase == "RUNNING":
                self.first_run_completed_at = timestamp
            elif phase == "STABLE":
                self.stable_achieved_at = timestamp
                self.consecutive_stable_days = 0

            logger.info("Phase transition", from_phase=old_phase, to_phase=phase)
            self.updated_at = timestamp

    def increment_stable_days(self) -> None:
        """Increment consecutive stable days counter."""
        self.consecutive_stable_days += 1
        if self.consecutive_stable_days >= 7 and self.phase != "STABLE":
            self.set_phase("STABLE")

    def is_stable(self, error_rate_threshold: float = 0.01, consecutive_days: int = 7) -> bool:
        """Check if deployment is considered stable.

        Args:
            error_rate_threshold: Max error rate for stability
            consecutive_days: Days required for stability

        Returns:
            True if stable
        """
        return (
            self.phase == "STABLE"
            and self.consecutive_stable_days >= consecutive_days
            and self.error_rate < error_rate_threshold
        )


def load_state(state_path: str) -> FlywheelState:
    """Load flywheel state from file.

    Args:
        state_path: Path to state file

    Returns:
        FlywheelState instance (new if file doesn't exist)
    """
    path = Path(state_path)

    if not path.is_file():
        logger.info("No existing state file, creating new state", path=str(state_path))
        return FlywheelState()

    try:
        with open(path, "r") as f:
            data = json.load(f)
        logger.debug(
            "Loaded state",
            path=str(path),
            phase=data.get("phase", "UNKNOWN"),
            runs=data.get("total_runs", 0),
        )
        return FlywheelState.from_dict(data)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load state, creating new", path=str(path), error=str(e))
        return FlywheelState()


def save_state(state: FlywheelState, state_path: str) -> None:
    """Save flywheel state to file.

    Args:
        state: FlywheelState to save
        state_path: Path to state file
    """
    path = Path(state_path)
    state.updated_at = datetime.utcnow().isoformat() + "Z"

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)
        logger.debug("Saved state", path=str(path), runs=state.total_runs)
    except OSError as e:
        logger.error("Failed to save state", path=str(path), error=str(e))