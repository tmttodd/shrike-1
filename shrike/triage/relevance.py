"""Relevance scoring for individual OCSF events.

Produces a 0.0-1.0 score from four weighted components:
  - subtype_score (0.4): activity_id + class_uid combination value
  - field_richness (0.3): ratio of security-relevant fields present
  - attack_coverage (0.2): does this event enable ATT&CK technique detection?
  - source_reputation (0.1): configurable per source type
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shrike.evaluate.attack_coverage import ATTACK_TECHNIQUE_MAP
from shrike.evaluate.types import get_nested


@dataclass
class RelevanceResult:
    """Output of relevance scoring for a single event."""
    score: float                          # 0.0 - 1.0 composite
    components: dict[str, float]          # Individual component scores
    matched_techniques: list[str]         # ATT&CK technique IDs this event enables
    source_type: str                      # Detected or provided source type

    def to_dict(self) -> dict[str, Any]:
        return {
            "relevance_score": round(self.score, 4),
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "matched_techniques": self.matched_techniques,
            "source_type": self.source_type,
        }


# --- Subtype scoring ---
# Maps (class_uid, activity_id) to a value score.
# Higher = more security-relevant event subtype.
# Unknown combos default to 0.5.

SUBTYPE_SCORES: dict[tuple[int, int], float] = {
    # Authentication (3002)
    (3002, 1): 1.0,   # Logon
    (3002, 2): 0.6,   # Logoff
    (3002, 3): 0.4,   # Authentication Ticket (Kerberos TGT)
    (3002, 4): 0.4,   # Service Ticket
    # Account Lifecycle (3001)
    (3001, 1): 1.0,   # Create
    (3001, 2): 0.9,   # Enable
    (3001, 3): 0.8,   # Password Change
    (3001, 4): 0.7,   # Password Reset
    (3001, 5): 0.6,   # Disable
    (3001, 6): 0.9,   # Delete
    # Authorization / Access Control (3003)
    (3003, 1): 0.8,   # Assign Privileges
    (3003, 2): 0.8,   # Revoke Privileges
    # Process Activity (1007)
    (1007, 1): 0.9,   # Launch / Create
    (1007, 2): 0.3,   # Terminate
    # Network Activity (4001)
    (4001, 1): 0.7,   # Open
    (4001, 2): 0.3,   # Close
    (4001, 3): 0.4,   # Reset
    (4001, 5): 0.5,   # Refuse
    # DNS Activity (4003)
    (4003, 1): 0.6,   # Query
    (4003, 2): 0.5,   # Response
    # HTTP Activity (4002)
    (4002, 1): 0.6,   # Connect / Request
    (4002, 2): 0.5,   # Response
    # Finding (2004)
    (2004, 1): 1.0,   # Create (new finding = high value)
    (2004, 2): 0.4,   # Update
    # API Activity (6003)
    (6003, 1): 0.8,   # Create
    (6003, 2): 0.7,   # Read
    (6003, 3): 0.8,   # Update
    (6003, 4): 0.9,   # Delete
    # System Activity (1001)
    (1001, 1): 0.1,   # Startup
    (1001, 2): 0.1,   # Shutdown
    # Scheduled Job (1006)
    (1006, 1): 0.8,   # Create
    (1006, 2): 0.4,   # Run
    (1006, 3): 0.7,   # Delete
    # Group Management (3004)
    (3004, 1): 0.9,   # Assign
    (3004, 2): 0.9,   # Revoke
    # Privilege Use (3005)
    (3005, 1): 0.9,   # Escalation
}

DEFAULT_SUBTYPE_SCORE = 0.5

# --- Security-relevant fields ---
# Fields that carry detection value when present.
# Organized by how much they matter for security analysis.

SECURITY_FIELDS: list[str] = [
    "user.name",
    "user.uid",
    "actor.user.name",
    "actor.user.uid",
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "process.name",
    "process.cmd_line",
    "process.pid",
    "process.parent_process.name",
    "process.parent_process.pid",
    "process.file.path",
    "finding_info.title",
    "finding_info.uid",
    "severity_id",
    "status",
    "status_id",
    "auth_protocol",
    "auth_protocol_id",
    "connection_info.protocol_name",
    "connection_info.direction",
    "http_request.url.path",
    "http_request.http_method",
    "http_response.code",
    "query.hostname",
    "answers",
    "traffic.bytes_in",
    "traffic.bytes_out",
    "email.from",
    "email.to",
    "api.operation",
    "api.service.name",
    "privileges",
    "session.uid",
    "device.hostname",
    "observables",
    "unmapped",
]

# Per-class expected field counts (approximate max for normalization).
# This prevents penalizing event types that naturally have fewer fields.
CLASS_MAX_FIELDS: dict[int, int] = {
    3002: 12,  # Authentication — user, src, dst, status, auth_protocol, etc.
    3001: 8,   # Account Lifecycle
    3003: 8,   # Authorization
    1007: 12,  # Process Activity — process, parent, cmd_line, file, user
    4001: 12,  # Network Activity — src, dst, ports, protocol, traffic
    4003: 8,   # DNS Activity
    4002: 10,  # HTTP Activity
    2004: 10,  # Vulnerability Finding
    6003: 8,   # API Activity
    1001: 4,   # System Activity — minimal fields
    1006: 6,   # Scheduled Job
    3004: 6,   # Group Management
    3005: 6,   # Privilege Use
}

DEFAULT_MAX_FIELDS = 10

# --- Source reputation ---
# How trustworthy / security-relevant is this source?

DEFAULT_SOURCE_REPUTATION: dict[str, float] = {
    "sysmon": 0.95,
    "windows_security": 0.90,
    "palo_alto": 0.90,
    "crowdstrike": 0.95,
    "okta": 0.85,
    "duo": 0.85,
    "suricata": 0.90,
    "zeek": 0.85,
    "sshd": 0.75,
    "auditd": 0.80,
    "firewall": 0.80,
    "dns_server": 0.60,
    "web_server": 0.50,
    "apache": 0.50,
    "nginx": 0.50,
    "application": 0.40,
    "healthcheck": 0.10,
    "heartbeat": 0.05,
    "metric": 0.10,
    "debug": 0.05,
}

DEFAULT_SOURCE_SCORE = 0.5


class RelevanceScorer:
    """Scores OCSF events on a 0.0-1.0 relevance scale.

    Args:
        source_reputation: Optional override for source reputation scores.
        weights: Optional override for component weights.
            Defaults: subtype=0.4, field_richness=0.3, attack_coverage=0.2, source_reputation=0.1
    """

    def __init__(
        self,
        source_reputation: dict[str, float] | None = None,
        weights: dict[str, float] | None = None,
    ):
        self._source_rep = {**DEFAULT_SOURCE_REPUTATION}
        if source_reputation:
            self._source_rep.update(source_reputation)

        self._weights = weights or {
            "subtype_score": 0.4,
            "field_richness": 0.3,
            "attack_coverage": 0.2,
            "source_reputation": 0.1,
        }

        # Pre-build class→technique index for fast lookup
        self._class_technique_index = _build_class_technique_index()

    def score(self, event: dict[str, Any], source_type: str = "") -> RelevanceResult:
        """Score a single OCSF event.

        Args:
            event: OCSF-normalized event dict.
            source_type: Optional source type hint (e.g., "sysmon", "healthcheck").
                If empty, attempts to infer from event metadata.

        Returns:
            RelevanceResult with composite score and component breakdown.
        """
        class_uid = event.get("class_uid", 0)
        activity_id = event.get("activity_id", 0)

        if not source_type:
            source_type = self._infer_source_type(event)

        subtype = self._score_subtype(class_uid, activity_id)
        richness = self._score_field_richness(event, class_uid)
        attack, matched_techniques = self._score_attack_coverage(event, class_uid)
        source_rep = self._score_source_reputation(source_type)

        components = {
            "subtype_score": subtype,
            "field_richness": richness,
            "attack_coverage": attack,
            "source_reputation": source_rep,
        }

        composite = sum(
            components[k] * self._weights[k] for k in self._weights
        )
        composite = max(0.0, min(1.0, composite))

        return RelevanceResult(
            score=composite,
            components=components,
            matched_techniques=matched_techniques,
            source_type=source_type,
        )

    def _score_subtype(self, class_uid: int, activity_id: int) -> float:
        """Score based on event subtype (class + activity combination)."""
        return SUBTYPE_SCORES.get((class_uid, activity_id), DEFAULT_SUBTYPE_SCORE)

    def _score_field_richness(self, event: dict, class_uid: int) -> float:
        """Score based on presence of security-relevant fields."""
        present = 0
        for field_path in SECURITY_FIELDS:
            val = get_nested(event, field_path)
            if val is not None and str(val) not in ("", "None", "unknown", "0"):
                present += 1

        max_fields = CLASS_MAX_FIELDS.get(class_uid, DEFAULT_MAX_FIELDS)
        return min(present / max_fields, 1.0)

    def _score_attack_coverage(
        self, event: dict, class_uid: int
    ) -> tuple[float, list[str]]:
        """Score based on ATT&CK technique enablement.

        Checks whether this event's class and populated fields satisfy
        the detection requirements for any ATT&CK technique.
        """
        if class_uid == 0:
            return 0.0, []

        candidate_techniques = self._class_technique_index.get(class_uid, [])
        if not candidate_techniques:
            return 0.0, []

        matched = []
        for tech_id, class_req in candidate_techniques:
            required = class_req["required_fields"]
            activity_filter = class_req.get("activity_filter")

            # Check activity filter
            if activity_filter:
                event_activity = event.get("activity_id", 0)
                if event_activity not in activity_filter:
                    continue

            # Check required fields
            fields_present = 0
            for field_path in required:
                val = get_nested(event, field_path)
                if val is not None and str(val) not in ("", "None", "unknown", "0"):
                    fields_present += 1

            if fields_present == len(required):
                matched.append(tech_id)

        if not matched:
            return 0.0, []

        # Score: more techniques enabled = higher score, capped at 1.0
        # 1 technique = 0.5, 2 = 0.75, 3+ = 1.0
        score = min(0.25 + 0.25 * len(matched), 1.0)
        return score, matched

    def _score_source_reputation(self, source_type: str) -> float:
        """Score based on source type reputation."""
        return self._source_rep.get(source_type.lower(), DEFAULT_SOURCE_SCORE)

    def _infer_source_type(self, event: dict) -> str:
        """Best-effort inference of source type from event metadata."""
        # Check metadata.product.name
        product = get_nested(event, "metadata.product.name")
        if product and isinstance(product, str):
            return product.lower().replace(" ", "_")

        # Check metadata.log_name
        log_name = get_nested(event, "metadata.log_name")
        if log_name and isinstance(log_name, str):
            return log_name.lower().replace(" ", "_")

        # Check device.type or similar
        device_type = get_nested(event, "device.type")
        if device_type:
            return device_type.lower().replace(" ", "_")

        return ""


def _build_class_technique_index() -> dict[int, list[tuple[str, dict]]]:
    """Build a class_uid → [(technique_id, class_req)] index for fast lookup."""
    index: dict[int, list[tuple[str, dict]]] = {}
    for tech_id, tech in ATTACK_TECHNIQUE_MAP.items():
        for class_req in tech["ocsf_classes"]:
            cls_uid = class_req["class_uid"]
            if cls_uid not in index:
                index[cls_uid] = []
            index[cls_uid].append((tech_id, class_req))
    return index
