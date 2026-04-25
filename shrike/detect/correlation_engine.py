"""Correlation engine — orchestrates Sigma rules, patterns, and anomaly detection."""

from __future__ import annotations

import yaml
from typing import Any

from shrike.detect.alert import CorrelationAlert
from shrike.detect.sigma.rule_engine import SigmaRuleEngine


class CorrelationEngine:
    """Orchestrates correlation detection across Sigma rules and patterns.

    Usage:
        engine = CorrelationEngine(config_path="/etc/shrike/detect-config.yaml")
        alerts = engine.process(ocsf_event)
        for alert in alerts:
            handle_alert(alert)
    """

    def __init__(
        self,
        config_path: str | None = None,
        sigma_rules_dir: str | None = None,
        enabled: bool = True,
    ):
        """Initialize correlation engine.

        Args:
            config_path: Path to YAML config file.
            sigma_rules_dir: Directory containing Sigma YAML rules.
            enabled: Whether correlation is enabled.
        """
        self.enabled = enabled
        self._sigma_engine: SigmaRuleEngine | None = None

        # Load config if provided
        if config_path:
            self._load_config(config_path)
        elif sigma_rules_dir:
            self._sigma_engine = SigmaRuleEngine(rules_dir=sigma_rules_dir)

    def _load_config(self, config_path: str) -> None:
        """Load configuration from YAML file."""
        with open(config_path) as f:
            config = yaml.safe_load(f)

        detect_config = config.get("correlation", {})
        self.enabled = detect_config.get("enabled", True)

        sigma_config = detect_config.get("sigma", {})
        if sigma_config.get("enabled", True):
            rule_dirs = sigma_config.get("rule_dirs", [])
            if rule_dirs:
                self._sigma_engine = SigmaRuleEngine(rules_dir=rule_dirs[0])

    def process(self, event: dict[str, Any]) -> list[CorrelationAlert]:
        """Process an OCSF event through all correlation layers.

        Args:
            event: OCSF-normalized event dict.

        Returns:
            List of CorrelationAlerts (may be empty if no matches).
        """
        if not self.enabled:
            return []

        alerts: list[CorrelationAlert] = []

        # Sigma rule matching
        if self._sigma_engine:
            sigma_alerts = self._sigma_engine.match(event)
            alerts.extend(sigma_alerts)

        return alerts

    def process_batch(self, events: list[dict[str, Any]]) -> list[CorrelationAlert]:
        """Process a batch of events.

        Args:
            events: List of OCSF-normalized event dicts.

        Returns:
            List of CorrelationAlerts.
        """
        all_alerts: list[CorrelationAlert] = []
        for event in events:
            all_alerts.extend(self.process(event))
        return all_alerts

    def add_sigma_rules(self, rules_dir: str) -> None:
        """Add or update Sigma rules from directory.

        Args:
            rules_dir: Directory containing Sigma YAML files.
        """
        if self._sigma_engine:
            self._sigma_engine.load_rules(rules_dir)
        else:
            self._sigma_engine = SigmaRuleEngine(rules_dir=rules_dir)

    def get_stats(self) -> dict[str, Any]:
        """Get correlation engine statistics."""
        stats = {
            "enabled": self.enabled,
            "sigma_rules_loaded": 0,
        }
        if self._sigma_engine:
            stats["sigma_rules_loaded"] = len(self._sigma_engine.rules)
        return stats
