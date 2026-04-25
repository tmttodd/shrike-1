"""Flywheel detectors — generic detection components.

Provides generic detectors that work for any project:
- HTTPHealthDetector: HTTP health endpoint polling
- ProcessLogDetector: Log file ERROR detection
- GitHubClient: GitHub issue creation

Project-specific detectors inherit from Detector base.
"""

from flywheel.detectors.base import Detector, DetectorResult, IssueSignature, compute_signature_hash
from flywheel.detectors.github import GitHubClient
from flywheel.detectors.http import HTTPHealthDetector
from flywheel.detectors.process import ProcessLogDetector

__all__ = [
    "Detector",
    "DetectorResult",
    "IssueSignature",
    "compute_signature_hash",
    "GitHubClient",
    "HTTPHealthDetector",
    "ProcessLogDetector",
]