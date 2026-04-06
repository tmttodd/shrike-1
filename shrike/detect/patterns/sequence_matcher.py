"""Multi-event sequence matching for attack pattern detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from shrike.detect.alert import CorrelationAlert
from shrike.evaluate.types import get_nested


@dataclass
class SequencePattern:
    """Definition of a multi-event attack pattern."""
    name: str
    description: str
    window_seconds: int  # Time window for sequence completion
    correlation_key: list[str]  # Fields used to group events (e.g., ["src_endpoint.ip", "user.name"])
    sequence: list[dict[str, Any]]  # Expected event sequence
    threshold: int  # Number of sequence completions to trigger alert
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)


@dataclass
class SequenceState:
    """Tracks state for a single sequence being assembled."""
    pattern_name: str
    correlation_value: tuple  # Values for correlation key fields
    current_step: int  # Current position in sequence
    first_event_time: datetime
    events: list[dict[str, Any]] = field(default_factory=list)


class SequenceMatcher:
    """Detects multi-event attack sequences.

    Usage:
        matcher = SequenceMatcher()
        matcher.add_pattern(BRUTE_FORCE_PATTERN)

        for event in event_stream:
            alerts = matcher.process(event)
            for alert in alerts:
                handle_alert(alert)
    """

    # Built-in attack patterns
    BRUTE_FORCE = SequencePattern(
        name="Brute Force Attack",
        description="Multiple failed authentication attempts followed by success",
        window_seconds=300,  # 5 minutes
        correlation_key=["src_endpoint.ip", "user.name"],
        sequence=[
            {"class_uid": 3002, "status_id": 9},  # Failed auth
            {"class_uid": 3002, "status_id": 9},  # Failed auth
            {"class_uid": 3002, "status_id": 9},  # Failed auth
            {"class_uid": 3002, "status_id": 1},  # Success
        ],
        threshold=1,
        mitre_techniques=["T1110.001"],  # Brute Force: Password Guessing
        mitre_tactics=["TA0006"],  # Credential Access
    )

    LATERAL_MOVEMENT = SequencePattern(
        name="Lateral Movement",
        description="SSH connections from compromised host to multiple internal systems",
        window_seconds=600,  # 10 minutes
        correlation_key=["device.hostname", "user.name"],
        sequence=[
            {"class_uid": 3002, "status_id": 1},  # Auth success (initial compromise)
            {"class_uid": 4001, "activity_id": 1},  # Network connection (SSH)
            {"class_uid": 4001, "activity_id": 1},  # Network connection (SSH)
            {"class_uid": 4001, "activity_id": 1},  # Network connection (SSH)
        ],
        threshold=1,
        mitre_techniques=["T1021.004"],  # Remote Services: SSH
        mitre_tactics=["TA0008"],  # Lateral Movement
    )

    PRIVILEGE_ESCALATION = SequencePattern(
        name="Privilege Escalation",
        description="User gains elevated privileges after initial access",
        window_seconds=1800,  # 30 minutes
        correlation_key=["user.name"],
        sequence=[
            {"class_uid": 3002, "status_id": 1},  # Initial auth
            {"class_uid": 1007, "activity_id": 1},  # Process launch
            {"class_uid": 3005, "activity_id": 1},  # Privilege escalation
        ],
        threshold=1,
        mitre_techniques=["T1068"],  # Exploitation for Privilege Escalation
        mitre_tactics=["TA0004"],  # Privilege Escalation
    )

    def __init__(self):
        """Initialize sequence matcher."""
        self._patterns: list[SequencePattern] = []
        self._states: dict[str, SequenceState] = {}  # key -> SequenceState
        self._cleanup_threshold = 10000  # Max states before cleanup

        # Register built-in patterns
        self.add_pattern(self.BRUTE_FORCE)
        self.add_pattern(self.LATERAL_MOVEMENT)
        self.add_pattern(self.PRIVILEGE_ESCALATION)

    def add_pattern(self, pattern: SequencePattern) -> None:
        """Add a sequence pattern for detection.

        Args:
            pattern: SequencePattern to add.
        """
        self._patterns.append(pattern)

    def process(self, event: dict[str, Any]) -> list[CorrelationAlert]:
        """Process an event through all sequence patterns.

        Args:
            event: OCSF-normalized event.

        Returns:
            List of CorrelationAlerts for completed sequences.
        """
        alerts: list[CorrelationAlert] = []

        # Check against all patterns
        for pattern in self._patterns:
            pattern_alerts = self._check_pattern(pattern, event)
            alerts.extend(pattern_alerts)

        # Periodic cleanup
        if len(self._states) > self._cleanup_threshold:
            self._cleanup_old_states()

        return alerts

    def _check_pattern(
        self, pattern: SequencePattern, event: dict[str, Any]
    ) -> list[CorrelationAlert]:
        """Check an event against a specific pattern.

        Args:
            pattern: SequencePattern to check.
            event: OCSF event.

        Returns:
            List of CorrelationAlerts for completed sequences.
        """
        alerts: list[CorrelationAlert] = []

        # Get correlation key value
        corr_value = self._get_correlation_value(event, pattern.correlation_key)
        if corr_value is None:
            return alerts

        # Create state key
        state_key = f"{pattern.name}:{corr_value}"

        # Get or create sequence state
        if state_key not in self._states:
            # Check if this event matches the first step of the sequence
            if self._event_matches_step(event, pattern.sequence[0]):
                self._states[state_key] = SequenceState(
                    pattern_name=pattern.name,
                    correlation_value=corr_value,
                    current_step=1,  # First step matched
                    first_event_time=self._get_event_time(event),
                    events=[event],
                )
        else:
            state = self._states[state_key]

            # Check if window expired
            event_time = self._get_event_time(event)
            if event_time - state.first_event_time > timedelta(seconds=pattern.window_seconds):
                # Window expired, reset state
                state.current_step = 0
                state.first_event_time = event_time
                state.events = [event]

            # Check if event matches current step
            if self._event_matches_step(event, pattern.sequence[state.current_step]):
                state.events.append(event)
                state.current_step += 1

                # Check if sequence complete
                if state.current_step >= len(pattern.sequence):
                    # Sequence completed!
                    alert = self._create_sequence_alert(pattern, state)
                    alerts.append(alert)

                    # Reset state for next detection
                    state.current_step = 0
                    state.first_event_time = event_time
                    state.events = [event]

        return alerts

    def _get_correlation_value(
        self, event: dict[str, Any], key_fields: list[str]
    ) -> tuple | None:
        """Get correlation key value from event.

        Args:
            event: OCSF event.
            key_fields: List of field paths for correlation key.

        Returns:
            Tuple of field values or None if any field missing.
        """
        values = []
        for field_path in key_fields:
            value = get_nested(event, field_path)
            if value is None:
                return None
            values.append(str(value))

        return tuple(values)

    def _event_matches_step(self, event: dict[str, Any], step: dict[str, Any]) -> bool:
        """Check if event matches a sequence step.

        Args:
            event: OCSF event.
            step: Sequence step definition.

        Returns:
            True if event matches step criteria.
        """
        for field_path, expected_value in step.items():
            actual_value = get_nested(event, field_path)
            if actual_value != expected_value:
                return False
        return True

    def _get_event_time(self, event: dict[str, Any]) -> datetime:
        """Extract timestamp from event.

        Args:
            event: OCSF event.

        Returns:
            datetime or epoch start if missing.
        """
        time_val = event.get("time")
        if isinstance(time_val, datetime):
            return time_val
        if isinstance(time_val, (int, float)):
            return datetime.fromtimestamp(time_val)
        return datetime.now()

    def _create_sequence_alert(
        self, pattern: SequencePattern, state: SequenceState
    ) -> CorrelationAlert:
        """Create alert for completed sequence.

        Args:
            pattern: Completed SequencePattern.
            state: SequenceState that completed.

        Returns:
            CorrelationAlert.
        """
        return CorrelationAlert(
            alert_id=f"pattern-{pattern.name}-{id(state)}",
            timestamp=state.events[-1].get("time", ""),
            correlation_type="pattern",
            severity="high",
            title=pattern.name,
            description=pattern.description,
            matched_patterns=[pattern.name],
            observables=[{"name": k, "value": v} for k, v in zip(pattern.correlation_key, state.correlation_value)],
            event_count=len(state.events),
            mitre_techniques=pattern.mitre_techniques,
            mitre_tactics=pattern.mitre_tactics,
            event_ids=[e.get("event_id", "") for e in state.events],
        )

    def _cleanup_old_states(self) -> None:
        """Remove old sequence states to prevent memory bloat."""
        now = datetime.now()
        states_to_keep = {}

        for key, state in self._states.items():
            # Keep states that are still within their pattern's window
            for pattern in self._patterns:
                if pattern.name == state.pattern_name:
                    age = (now - state.first_event_time).total_seconds()
                    if age < pattern.window_seconds:
                        states_to_keep[key] = state
                    break

        self._states = states_to_keep
