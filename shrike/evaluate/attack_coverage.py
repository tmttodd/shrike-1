"""ATT&CK detection coverage — maps OCSF extraction quality to ATT&CK visibility.

Given what Shrike extracts (OCSF classes + field depth), determines which
ATT&CK techniques are detectable and which are blind spots.

This is the "forward" direction of the evaluation framework:
- Inward = how good is the engine
- Outward = how good are the sources
- Forward = what can you DETECT with what you have

Usage:
    from shrike.evaluate.attack_coverage import measure_attack_coverage
    score = measure_attack_coverage(results)
    # score.metadata["technique_coverage"] = {
    #   "T1110": {"name": "Brute Force", "status": "covered", "confidence": 0.93},
    #   "T1571": {"name": "Non-Standard Port", "status": "blind", "reason": "dst_endpoint.port missing in 60%"},
    # }
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from shrike.evaluate.types import DimensionScore, FailureDetail, get_nested


# ATT&CK Technique → Detection Requirements
# Each technique needs specific OCSF classes AND specific fields to be detectable.
# Format: technique_id → {name, tactic, ocsf_classes: [{class_uid, required_fields, nice_to_have}]}
#
# This is a curated subset of the Enterprise ATT&CK matrix focused on
# techniques that are detectable from log data (not endpoint telemetry).

# detection_type values:
#   "single_event" — detectable from one normalized event (Shrike's direct value)
#   "behavioral"   — requires correlation/aggregation across events (Shrike provides the data,
#                     detection engine provides the logic)
#   "enriched"     — requires enrichment beyond normalization (threat intel, GeoIP, baseline)

ATTACK_TECHNIQUE_MAP: dict[str, dict[str, Any]] = {
    # --- Initial Access ---
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3002, "required_fields": ["user", "src_endpoint.ip", "status"],
             "nice_to_have": ["actor.user.uid", "auth_protocol"],
             "activity_filter": [1]},  # Only Logon events — not session close, not service auth
        ],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3002, "required_fields": ["user", "src_endpoint.ip"],
             "nice_to_have": ["src_endpoint.port", "auth_protocol"],
             "activity_filter": [1]},  # Logon only
            {"class_uid": 4007, "required_fields": ["src_endpoint.ip"],
             "nice_to_have": ["user", "src_endpoint.port"]},
        ],
    },

    # --- Execution ---
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 1007, "required_fields": ["process.name", "process.cmd_line"],
             "nice_to_have": ["process.pid", "actor.user.name"],
             "activity_filter": [1]},  # Launch only — not terminate, not metric
        ],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 1006, "required_fields": ["user", "process.cmd_line"],
             "nice_to_have": ["process.pid", "time"]},
        ],
    },

    # --- Persistence ---
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3001, "required_fields": ["user", "activity_name"],
             "nice_to_have": ["actor.user.name", "time"]},
            {"class_uid": 6003, "required_fields": ["api.operation"],
             "nice_to_have": ["actor.user.name", "src_endpoint.ip"]},
        ],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3001, "required_fields": ["user", "activity_name"],
             "nice_to_have": ["actor.user.name"],
             "activity_filter": [1]},  # Create activity only
        ],
    },

    # --- Privilege Escalation ---
    "T1055": {
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 1007, "required_fields": ["process.name", "process.parent_process.name"],
             "nice_to_have": ["process.cmd_line", "process.pid"],
             "activity_filter": [1]},  # Launch only
        ],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3005, "required_fields": ["user", "privileges"],
             "nice_to_have": ["actor.user.name"]},
        ],
    },

    # --- Defense Evasion ---
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 1008, "required_fields": ["activity_name"],
             "nice_to_have": ["user", "device.hostname"]},
        ],
    },

    # --- Credential Access ---
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 3002, "required_fields": ["user", "src_endpoint.ip", "status"],
             "nice_to_have": ["time", "auth_protocol"],
             "activity_filter": [1]},  # Logon attempts only
        ],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 1007, "required_fields": ["process.name", "process.cmd_line"],
             "nice_to_have": ["process.file.path", "actor.user.name"],
             "activity_filter": [1]},  # Launch only
        ],
    },

    # --- Discovery ---
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port"],
             "nice_to_have": ["connection_info.protocol_name"],
             "activity_filter": [1, 2, 6]},  # Open, Close, Traffic — not refuse/reset
        ],
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4003, "required_fields": ["query.hostname"],
             "nice_to_have": ["src_endpoint.ip", "answers.rdata"]},
        ],
    },

    # --- Lateral Movement ---
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3002, "required_fields": ["user", "src_endpoint.ip"],
             "nice_to_have": ["auth_protocol", "dst_endpoint.ip"],
             "activity_filter": [1]},  # Logon only
            {"class_uid": 4007, "required_fields": ["src_endpoint.ip", "user"],
             "nice_to_have": ["dst_endpoint.ip"]},
        ],
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactic": "Lateral Movement",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 3003, "required_fields": ["session.uid", "user"],
             "nice_to_have": ["src_endpoint.ip"]},
        ],
    },

    # --- Collection ---
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4009, "required_fields": ["email.from", "email.to"],
             "nice_to_have": ["src_endpoint.ip"]},
        ],
    },

    # --- Command and Control ---
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["src_endpoint.ip", "dst_endpoint.ip"],
             "nice_to_have": ["dst_endpoint.port", "connection_info.protocol_name"]},
            {"class_uid": 4003, "required_fields": ["query.hostname"],
             "nice_to_have": ["src_endpoint.ip"]},
        ],
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["dst_endpoint.ip", "dst_endpoint.port"],
             "nice_to_have": ["src_endpoint.ip", "connection_info.protocol_name"],
             "activity_filter": [1, 2, 6]},  # Connection events only
        ],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port"],
             "nice_to_have": ["connection_info.protocol_name"]},
        ],
    },

    # --- Exfiltration ---
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["src_endpoint.ip", "dst_endpoint.ip", "traffic.bytes_out"],
             "nice_to_have": ["dst_endpoint.port"]},
        ],
    },

    # --- Impact ---
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "detection_type": "single_event",
        "ocsf_classes": [
            {"class_uid": 6002, "required_fields": ["app.name", "activity_name"],
             "nice_to_have": ["user", "device.hostname"]},
        ],
    },

    # --- Detection-specific ---
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "detection_type": "enriched",
        "ocsf_classes": [
            {"class_uid": 2004, "required_fields": ["finding_info.title"],
             "nice_to_have": ["src_endpoint.ip", "dst_endpoint.ip", "severity_id"]},
            {"class_uid": 4002, "required_fields": ["http_request.url.path", "src_endpoint.ip"],
             "nice_to_have": ["http_response.code"]},
        ],
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "detection_type": "behavioral",
        "ocsf_classes": [
            {"class_uid": 4001, "required_fields": ["src_endpoint.ip", "dst_endpoint.ip"],
             "nice_to_have": ["dst_endpoint.port"]},
            {"class_uid": 2004, "required_fields": ["finding_info.title", "src_endpoint.ip"],
             "nice_to_have": ["severity_id"]},
        ],
    },
}


def measure_attack_coverage(
    results: list[tuple[Any | None, dict]],
) -> DimensionScore:
    """Dimension 9: ATT&CK technique detection coverage.

    For each ATT&CK technique, checks:
    1. Do we have events in the required OCSF class(es)?
    2. Do those events have the required fields populated?
    3. Technique is "covered" if we have class coverage AND field depth.

    Score = covered_techniques / total_techniques * 100
    """
    # Build per-class AND per-activity field availability stats
    # Key: (class_uid, activity_id_or_None) → {field: count}
    class_field_stats: dict[tuple, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    class_event_counts: dict[tuple, int] = defaultdict(int)

    for result, gt in results:
        if result is None:
            continue
        class_uid = gt.get("class_uid", 0)
        activity_id = get_nested(result.event, "activity_id") if result else None

        # Track both unfiltered (class_uid, None) and filtered (class_uid, activity_id)
        for key in [(class_uid, None), (class_uid, activity_id)]:
            class_event_counts[key] += 1
            event = result.event
            for field_path in _ALL_REQUIRED_FIELDS:
                val = get_nested(event, field_path)
                if val is not None and str(val) not in ("", "None", "unknown", "0"):
                    class_field_stats[key][field_path] += 1

    # Normalize to percentages
    class_field_pct: dict[tuple, dict[str, float]] = {}
    for key, fields in class_field_stats.items():
        count = class_event_counts[key]
        if count == 0:
            continue
        class_field_pct[key] = {
            field: (hits / count) for field, hits in fields.items()
        }

    # Score each technique
    covered = 0
    partial = 0
    blind = 0
    technique_details: dict[str, dict[str, Any]] = {}
    blind_techniques: list[FailureDetail] = []

    for tech_id, tech in ATTACK_TECHNIQUE_MAP.items():
        tech_name = tech["name"]
        tactic = tech["tactic"]

        # Check each OCSF class requirement (ANY class matching = technique covered)
        best_coverage = 0.0
        best_reason = ""

        for class_req in tech["ocsf_classes"]:
            cls_uid = class_req["class_uid"]
            required = class_req["required_fields"]
            nice_to_have = class_req.get("nice_to_have", [])
            activity_filter = class_req.get("activity_filter")

            # Select the right stat key based on activity_filter
            if activity_filter:
                # Only count events with matching activity_id
                # Use the best matching activity_id
                best_key = None
                best_count = 0
                for act_id in activity_filter:
                    key = (cls_uid, act_id)
                    if class_event_counts.get(key, 0) > best_count:
                        best_key = key
                        best_count = class_event_counts[key]
                if best_key is None or best_count == 0:
                    continue
                stat_key = best_key
            else:
                stat_key = (cls_uid, None)

            # Do we have events in this class?
            if class_event_counts.get(stat_key, 0) == 0:
                continue

            # Check required field availability
            field_pcts = class_field_pct.get(stat_key, {})
            required_coverage = []
            for field in required:
                pct = field_pcts.get(field, 0.0)
                required_coverage.append(pct)

            if not required_coverage:
                continue

            avg_required = sum(required_coverage) / len(required_coverage)

            # Nice-to-have boost (up to 20% bonus)
            nice_coverage = []
            for field in nice_to_have:
                pct = field_pcts.get(field, 0.0)
                nice_coverage.append(pct)
            avg_nice = (sum(nice_coverage) / len(nice_coverage)) if nice_coverage else 0
            bonus = avg_nice * 0.2

            coverage = min(avg_required + bonus, 1.0)
            if coverage > best_coverage:
                best_coverage = coverage
                if avg_required < 0.5:
                    missing = [f for f, p in zip(required, required_coverage) if p < 0.3]
                    best_reason = f"class {cls_uid}: {', '.join(missing)} missing"

        # Classify
        if best_coverage >= 0.7:
            status = "covered"
            covered += 1
        elif best_coverage >= 0.3:
            status = "partial"
            partial += 1
        else:
            status = "blind"
            blind += 1
            blind_techniques.append(FailureDetail(
                description=f"{tech_id} {tech_name} ({tactic})",
                count=1,
                field=best_reason or "no events in required OCSF class",
                category="detection_blind_spot",
            ))

        detection_type = tech.get("detection_type", "single_event")
        technique_details[tech_id] = {
            "name": tech_name,
            "tactic": tactic,
            "detection_type": detection_type,
            "status": status,
            "confidence": round(best_coverage, 2),
            "reason": best_reason if status != "covered" else "",
        }

    total = covered + partial + blind
    score = (covered / total * 100) if total > 0 else 0

    # Sub-scores by detection type
    single_event_techs = [t for t in technique_details.values()
                          if t["detection_type"] == "single_event"]
    behavioral_techs = [t for t in technique_details.values()
                        if t["detection_type"] == "behavioral"]
    enriched_techs = [t for t in technique_details.values()
                      if t["detection_type"] == "enriched"]

    single_covered = sum(1 for t in single_event_techs if t["status"] == "covered")
    behavioral_covered = sum(1 for t in behavioral_techs if t["status"] == "covered")
    enriched_covered = sum(1 for t in enriched_techs if t["status"] == "covered")

    normalization_score = (single_covered / len(single_event_techs) * 100
                           if single_event_techs else 0)
    detection_readiness = (behavioral_covered / len(behavioral_techs) * 100
                           if behavioral_techs else 0)

    # Group blind spots by tactic for the failure report
    tactic_gaps: dict[str, list[str]] = defaultdict(list)
    for tech_id, detail in technique_details.items():
        if detail["status"] == "blind":
            tactic_gaps[detail["tactic"]].append(f"{tech_id} {detail['name']}")

    failures = []
    for tactic, techs in sorted(tactic_gaps.items(), key=lambda x: -len(x[1])):
        failures.append(FailureDetail(
            description=f"{tactic}: {len(techs)} blind techniques — {', '.join(techs[:3])}",
            count=len(techs),
            category="tactic_gap",
        ))

    return DimensionScore(
        name="attack_coverage",
        score=score,
        total=total,
        passed=covered,
        failures=failures,
        metadata={
            "covered": covered,
            "partial": partial,
            "blind": blind,
            "normalization_coverage_pct": round(normalization_score, 1),
            "detection_readiness_pct": round(detection_readiness, 1),
            "single_event_techniques": len(single_event_techs),
            "behavioral_techniques": len(behavioral_techs),
            "enriched_techniques": len(enriched_techs),
            "techniques": technique_details,
            "note": "Two sub-scores: "
                    "normalization_coverage = single-event techniques where Shrike provides "
                    "all required fields (direct value of normalization). "
                    "detection_readiness = behavioral techniques where Shrike provides "
                    "the data needed for correlation rules (requires detection engine on top).",
        },
    )


# Collect all referenced fields for efficient lookup
_ALL_REQUIRED_FIELDS: set[str] = set()
for _tech in ATTACK_TECHNIQUE_MAP.values():
    for _cls in _tech["ocsf_classes"]:
        _ALL_REQUIRED_FIELDS.update(_cls["required_fields"])
        _ALL_REQUIRED_FIELDS.update(_cls.get("nice_to_have", []))
