#!/usr/bin/env python3
"""Auto-generate Shrike pattern YAML from Splunkbase TA extraction rules.

Reads props.conf EXTRACT- rules from downloaded TAs and combines them
with OCSF class mappings to produce pattern YAML files.

Usage:
    python scripts/generate_patterns_from_tas.py \
        --ta-dir data/ \
        --mappings data/ta_ocsf_mappings.json \
        --output patterns/
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# Splunk field name → OCSF field path mapping
# This is the bridge between TA extraction groups and OCSF semantics
SPLUNK_TO_OCSF = {
    # Network fields
    "src": "src_endpoint.ip",
    "src_ip": "src_endpoint.ip",
    "src_port": "src_endpoint.port",
    "source_ip": "src_endpoint.ip",
    "dest": "dst_endpoint.ip",
    "dest_ip": "dst_endpoint.ip",
    "dest_port": "dst_endpoint.port",
    "dest_nt_host": "dst_endpoint.hostname",
    "dest_mac": "dst_endpoint.mac",
    "transport": "connection_info.protocol_name",
    "protocol": "connection_info.protocol_name",
    "proto": "connection_info.protocol_name",
    "action": "activity_name",
    "vendor_action": "activity_name",
    "direction": "connection_info.direction",
    "bytes_in": "traffic.bytes_in",
    "bytes_out": "traffic.bytes_out",
    "packets_in": "traffic.packets_in",
    "packets_out": "traffic.packets_out",
    "duration": "duration",

    # Identity fields
    "user": "user",
    "src_user": "actor.user.name",
    "dest_user": "user",
    "dvc": "device.name",
    "dvc_ip": "device.ip",
    "signature": "finding_info.title",
    "signature_id": "finding_info.uid",
    "event_id": "metadata.event_code",
    "vendor_event_id": "metadata.event_code",

    # DNS fields
    "query": "query.hostname",
    "query_type": "query.type",
    "answer": "answers.rdata",
    "rcode": "rcode",
    "record_type": "query.type",
    "zone": "query.hostname",

    # HTTP fields
    "http_method": "http_request.http_method",
    "url": "http_request.url.path",
    "uri_path": "http_request.url.path",
    "status": "http_response.code",
    "http_user_agent": "http_request.user_agent",
    "http_referrer": "http_request.referrer",
    "http_content_type": "http_response.content_type",

    # DHCP fields
    "dest_mac": "dst_endpoint.mac",
    "lease_duration": "lease_dur",
    "msdhcp_id": "activity_id",
    "description": "message",

    # Process fields
    "process": "process.name",
    "process_id": "process.pid",
    "parent_process": "process.parent_process.name",
    "parent_process_id": "process.parent_process.pid",
    "command": "process.cmd_line",
    "file_path": "process.file.path",
    "file_hash": "process.file.hashes.value",

    # Auth fields
    "app": "auth_protocol",
    "reason": "status_detail",

    # Generic
    "msg": "message",
    "message": "message",
    "severity": "severity_id",
    "vendor_severity": "severity",
}

# OCSF class_uid → default static fields
CLASS_DEFAULTS = {
    3002: {
        "category_uid": 3,
        "category_name": "Identity & Access Management",
    },
    4001: {
        "category_uid": 4,
        "category_name": "Network Activity",
    },
    4002: {
        "category_uid": 4,
        "category_name": "Network Activity",
    },
    4003: {
        "category_uid": 4,
        "category_name": "Network Activity",
    },
    4004: {
        "category_uid": 4,
        "category_name": "Network Activity",
    },
    2004: {
        "category_uid": 2,
        "category_name": "Findings",
    },
    1007: {
        "category_uid": 1,
        "category_name": "System Activity",
    },
    6002: {
        "category_uid": 6,
        "category_name": "Application Activity",
    },
    6003: {
        "category_uid": 6,
        "category_name": "Application Activity",
    },
    5001: {
        "category_uid": 5,
        "category_name": "Discovery",
    },
}


def parse_props_conf(filepath: str) -> list[dict]:
    """Parse a Splunk props.conf file and extract EXTRACT- rules."""
    extractions = []
    current_stanza = "default"

    with open(filepath, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                current_stanza = line.strip("[]")
            elif line.startswith("EXTRACT-"):
                parts = line.split("=", 1)
                if len(parts) != 2:
                    continue
                name = parts[0].replace("EXTRACT-", "").strip()
                regex = parts[1].strip()

                # Convert Splunk regex syntax to Python
                # Splunk uses (?<name>...) instead of (?P<name>...)
                python_regex = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", regex)

                # Extract named groups
                groups = re.findall(r"\(\?P<(\w+)>", python_regex)

                # Test if regex compiles
                try:
                    re.compile(python_regex)
                    valid = True
                except re.error:
                    valid = False

                extractions.append({
                    "stanza": current_stanza,
                    "name": name,
                    "regex": python_regex,
                    "groups": groups,
                    "valid": valid,
                })

    return extractions


def guess_ocsf_class(stanza: str, groups: list[str], ta_name: str) -> tuple[int, str]:
    """Guess the OCSF class from stanza name and field groups."""
    stanza_lower = stanza.lower()
    groups_set = set(g.lower() for g in groups)

    # Network/firewall
    if any(k in stanza_lower for k in ["filterlog", "firewall", "traffic", "fw", "iptables"]):
        return 4001, "Network Activity"
    if any(k in groups_set for k in ["query", "query_type", "rcode", "zone"]):
        return 4003, "DNS Activity"
    if any(k in stanza_lower for k in ["dhcp"]):
        return 4004, "DHCP Activity"
    if any(k in stanza_lower for k in ["dns"]):
        return 4003, "DNS Activity"
    if any(k in stanza_lower for k in ["http", "web", "access"]):
        return 4002, "HTTP Activity"

    # Security
    if any(k in stanza_lower for k in ["security", "wineventlog:security"]):
        return 3002, "Authentication"
    if any(k in stanza_lower for k in ["threat", "alert", "detection", "ids", "ips"]):
        return 2004, "Detection Finding"

    # System
    if any(k in stanza_lower for k in ["syslog", "system"]):
        return 6002, "Application Lifecycle"

    # Default based on fields
    if "src" in groups_set or "dest" in groups_set or "src_ip" in groups_set:
        return 4001, "Network Activity"
    if "user" in groups_set or "src_user" in groups_set:
        return 3002, "Authentication"

    return 6002, "Application Lifecycle"


def build_field_map(groups: list[str]) -> dict[str, str]:
    """Map Splunk field names to OCSF paths."""
    field_map = {}
    for group in groups:
        ocsf_path = SPLUNK_TO_OCSF.get(group)
        if ocsf_path:
            field_map[group] = ocsf_path
        elif group not in ("pid", "raw", "event_id"):
            # Keep unmapped fields under unmapped.*
            field_map[group] = f"unmapped.{group}"
    return field_map


def generate_pattern_yaml(ta_name: str, extractions: list[dict]) -> dict:
    """Generate a Shrike pattern YAML structure from TA extractions."""
    # Group by stanza
    by_stanza = defaultdict(list)
    for ext in extractions:
        if ext["valid"] and len(ext["groups"]) >= 2:
            by_stanza[ext["stanza"]].append(ext)

    patterns = []
    for stanza, rules in by_stanza.items():
        for rule in rules:
            class_uid, class_name = guess_ocsf_class(stanza, rule["groups"], ta_name)
            field_map = build_field_map(rule["groups"])

            # Determine log format from stanza
            if "xml" in stanza.lower():
                log_formats = ["xml"]
            elif "json" in stanza.lower():
                log_formats = ["json"]
            elif "syslog" in stanza.lower() or "filterlog" in stanza.lower():
                log_formats = ["syslog_bsd", "syslog_rfc5424", "syslog_rfc3164"]
            else:
                log_formats = ["syslog_bsd", "syslog_rfc5424", "syslog_rfc3164", "kv", "custom"]

            static = {"severity_id": 1}
            static.update(CLASS_DEFAULTS.get(class_uid, {}))

            pattern = {
                "name": f"{ta_name}_{rule['name']}",
                "match": {
                    "log_format": log_formats,
                    "regex": rule["regex"],
                },
                "ocsf_class_uid": class_uid,
                "ocsf_class_name": class_name,
                "static": static,
                "field_map": {k: v for k, v in field_map.items() if not v.startswith("unmapped.")},
            }
            patterns.append(pattern)

    clean_name = ta_name.replace("ta_", "")
    return {
        "source": clean_name,
        "description": f"Auto-generated from Splunkbase TA: {ta_name}",
        "version": 1,
        "auto_generated": True,
        "patterns": patterns,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate patterns from Splunkbase TAs")
    parser.add_argument("--ta-dir", default="data/", help="Directory containing TA subdirs")
    parser.add_argument("--output", default="patterns/auto/", help="Output directory for generated patterns")
    parser.add_argument("--min-fields", type=int, default=2, help="Min captured fields to include")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    total_patterns = 0
    total_files = 0

    # Find all TAs with props.conf
    for ta_dir in sorted(os.listdir(args.ta_dir)):
        ta_path = os.path.join(args.ta_dir, ta_dir)
        if not os.path.isdir(ta_path) or not ta_dir.startswith("ta_"):
            continue

        # Find props.conf
        props_path = None
        for root, dirs, files in os.walk(ta_path):
            if "props.conf" in files:
                props_path = os.path.join(root, "props.conf")
                break

        if not props_path:
            continue

        # Parse extractions
        extractions = parse_props_conf(props_path)
        valid = [e for e in extractions if e["valid"] and len(e["groups"]) >= args.min_fields]

        if not valid:
            continue

        # Generate pattern YAML
        pattern_data = generate_pattern_yaml(ta_dir, valid)

        if not pattern_data["patterns"]:
            continue

        # Write YAML
        output_file = output_dir / f"{ta_dir.replace('ta_', '')}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(pattern_data, f, default_flow_style=False, sort_keys=False)

        print(f"  {ta_dir}: {len(pattern_data['patterns'])} patterns → {output_file.name}", file=sys.stderr)
        total_patterns += len(pattern_data["patterns"])
        total_files += 1

    print(f"\nGenerated {total_patterns} patterns in {total_files} files → {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
