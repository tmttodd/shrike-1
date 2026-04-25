"""Flywheel - Shrike continuous improvement detection system."""

from flywheel.state import FlywheelState, load_state, save_state
from flywheel.tracker import FlywheelTracker, TrackerConfig

__version__ = "0.1.0"

__all__ = [
    "FlywheelState",
    "FlywheelTracker",
    "TrackerConfig",
    "load_state",
    "save_state",
]