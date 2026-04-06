"""shrike.detect — Correlation engine for multi-event detection.

Provides Sigma rule matching, pattern correlation, and anomaly detection.

Usage:
    from shrike.detect import CorrelationEngine

    engine = CorrelationEngine(config_path="/etc/shrike/detect-config.yaml")
    alerts = engine.process(ocsf_event)
"""

from shrike.detect.alert import CorrelationAlert
from shrike.detect.correlation_engine import CorrelationEngine
from shrike.detect.sigma.rule_engine import SigmaRuleEngine
from shrike.detect.sigma.rule_loader import SigmaRuleLoader
from shrike.detect.patterns.sequence_matcher import SequenceMatcher

__all__ = [
    "CorrelationAlert",
    "CorrelationEngine",
    "SigmaRuleEngine",
    "SigmaRuleLoader",
    "SequenceMatcher",
]
