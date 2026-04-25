"""Flywheel — generic continuous improvement detection framework.

A reusable framework for detecting issues in deployed software.
Copy flywheel/ to any project, configure config.yaml, and override
detectors as needed. No project-specific code in the framework.

Example:
    from flywheel.config import FlywheelConfig
    from flywheel.framework import FlywheelFramework

    config = FlywheelConfig.from_yaml("config.yaml")
    framework = FlywheelFramework(config)
    framework.run_until_stable()
"""

from flywheel.config import FlywheelConfig
from flywheel.detectors.base import Detector, DetectorResult, IssueSignature
from flywheel.detectors.github import GitHubClient
from flywheel.framework import FlywheelFramework
from flywheel.state import FlywheelState, load_state, save_state

__version__ = "0.2.0"

__all__ = [
    # Config
    "FlywheelConfig",
    # Framework
    "FlywheelFramework",
    # State
    "FlywheelState",
    "load_state",
    "save_state",
    # Detectors
    "Detector",
    "DetectorResult",
    "IssueSignature",
    "GitHubClient",
]