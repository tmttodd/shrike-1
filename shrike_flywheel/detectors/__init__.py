"""Shrike-specific detectors for the flywheel system."""

from shrike_flywheel.detectors.logs import ShrikeLogDetector
from shrike_flywheel.detectors.shrike import ShrikeHealthDetector
from shrike_flywheel.detectors.splunk import SplunkDetector
from shrike_flywheel.detectors.wal import WalDetector

__all__ = [
    "ShrikeHealthDetector",
    "WalDetector",
    "ShrikeLogDetector",
    "SplunkDetector",
]