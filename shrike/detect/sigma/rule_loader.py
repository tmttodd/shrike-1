"""Load and parse Sigma rules from YAML files."""

from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any


class SigmaRuleLoader:
    """Loads Sigma rules from YAML files.

    Sigma rules are YAML files that define detection logic for security events.
    This loader parses them and converts to internal representation.
    """

    def __init__(self):
        self._loaded_rules: list[dict[str, Any]] = []

    def load_from_file(self, rule_path: str | Path) -> dict[str, Any]:
        """Load a single Sigma rule from file.

        Args:
            rule_path: Path to Sigma YAML file.

        Returns:
            Parsed rule dict with OCSF mapping.
        """
        path = Path(rule_path)
        with open(path) as f:
            raw = yaml.safe_load(f)

        return self._parse_rule(raw, path.name)

    def load_from_directory(self, rules_dir: str | Path) -> list[dict[str, Any]]:
        """Load all Sigma rules from a directory.

        Args:
            rules_dir: Directory containing Sigma YAML files.

        Returns:
            List of parsed rules.
        """
        dir_path = Path(rules_dir)
        rules = []

        for yaml_file in dir_path.glob("**/*.yml"):
            try:
                rule = self.load_from_file(yaml_file)
                rules.append(rule)
            except Exception as e:
                # Log error but continue loading other rules
                print(f"Warning: Failed to load {yaml_file}: {e}")

        for yaml_file in dir_path.glob("**/*.yaml"):
            try:
                rule = self.load_from_file(yaml_file)
                rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to load {yaml_file}: {e}")

        self._loaded_rules.extend(rules)
        return rules

    def _parse_rule(self, raw: dict[str, Any], source_file: str) -> dict[str, Any]:
        """Parse a raw Sigma rule into internal representation.

        Args:
            raw: Parsed YAML dict.
            source_file: Source filename for reference.

        Returns:
            Internal rule representation.
        """
        # Extract Sigma rule metadata
        rule = {
            "title": raw.get("title", "Untitled"),
            "id": raw.get("id", ""),
            "status": raw.get("status", "experimental"),
            "level": raw.get("level", "medium"),
            "description": raw.get("description", ""),
            "source_file": source_file,
            "logsource": raw.get("logsource", {}),
            "detection": raw.get("detection", {}),
            "falsepositives": raw.get("falsepositives", []),
            "references": raw.get("references", []),
            "tags": raw.get("tags", []),
        }

        # Extract MITRE ATT&CK mappings
        rule["mitre_techniques"] = self._extract_mitre_techniques(rule["tags"])
        rule["mitre_tactics"] = self._extract_mitre_tactics(rule["tags"])

        # Parse detection conditions
        rule["conditions"] = self._parse_detection_conditions(rule["detection"])

        return rule

    def _extract_mitre_techniques(self, tags: list[str]) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from tags.

        Sigma tags use format: attack.t1110.001 or attack.T1110
        """
        techniques = []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t"):
                # Extract technique ID (e.g., "attack.t1110.001" -> "T1110.001")
                tech_id = tag_lower.replace("attack.", "").upper()
                techniques.append(tech_id)
        return techniques

    def _extract_mitre_tactics(self, tags: list[str]) -> list[str]:
        """Extract MITRE ATT&CK tactic names from tags.

        Sigma tags use format: attack.defense_evasion, attack.persistence, etc.
        """
        tactic_map = {
            "defense_evasion": "TA0005",
            "persistence": "TA0003",
            "privilege_escalation": "TA0004",
            "credential_access": "TA0006",
            "lateral_movement": "TA0008",
            "initial_access": "TA0001",
            "execution": "TA0002",
            "discovery": "TA0007",
            "collection": "TA0009",
            "command_and_control": "TA0011",
            "exfiltration": "TA0010",
            "impact": "TA0040",
            "impact": "TA0040",
        }

        tactics = []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.") and tag_lower != "attack.t":
                tactic_name = tag_lower.replace("attack.", "")
                if tactic_name in tactic_map:
                    tactics.append(tactic_map[tactic_name])

        return tactics

    def _parse_detection_conditions(self, detection: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse Sigma detection conditions.

        Args:
            detection: Sigma detection section.

        Returns:
            List of parsed condition expressions.
        """
        conditions = []

        # Parse selection blocks
        selections = detection.get("selection", {})
        if isinstance(selections, dict):
            for sel_name, sel_criteria in selections.items():
                conditions.append({
                    "type": "selection",
                    "name": sel_name,
                    "criteria": sel_criteria,
                })

        # Parse condition expression
        condition_expr = detection.get("condition", "")
        conditions.append({
            "type": "condition",
            "expression": condition_expr,
        })

        return conditions
