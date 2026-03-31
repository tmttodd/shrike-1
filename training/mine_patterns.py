#!/usr/bin/env python3
"""Mine patterns from ground truth using Drain3 (syslog) + field fingerprinting (JSON).

Automatically discovers log templates and JSON field patterns from labeled
ground truth data and generates Shrike pattern YAML files.

Usage:
    python scripts/mine_patterns.py \
        --ground-truth data/ground_truth/classification_ground_truth.jsonl \
        --output patterns/mined/ \
        --min-samples 5 \
        --min-purity 0.8
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

# Reuse the OCSF field mapping from the TA generator
COMMON_FIELDS_TO_OCSF = {
    "EventID": "metadata.event_code",
    "LogHost": "device.hostname",
    "Computer": "device.hostname",
    "DomainName": "user.domain",
    "UserName": "user",
    "TargetUserName": "user",
    "SubjectUserName": "actor.user.name",
    "Source": "metadata.product.name",
    "LogonID": "session.uid",
    "LogonType": "logon_type_id",
    "ProcessID": "process.pid",
    "ParentProcessID": "process.parent_process.pid",
    "ProcessName": "process.name",
    "NewProcessName": "process.name",
    "CommandLine": "process.cmd_line",
    "ServiceName": "service.name",
    "IpAddress": "src_endpoint.ip",
    "src_ip": "src_endpoint.ip",
    "dest_ip": "dst_endpoint.ip",
    "src_port": "src_endpoint.port",
    "dest_port": "dst_endpoint.port",
    "activityDisplayName": "activity_name",
    "activityDateTime": "time",
    "category": "finding_info.types",
    "severity": "severity",
    "operationName": "api.operation",
    "time": "time",
    "timestamp": "time",
    "@timestamp": "time",
    "Time": "time",
    "host": "device.hostname",
    "hostname": "device.hostname",
    "user": "user",
    "action": "activity_name",
    "msg": "message",
    "message": "message",
    "level": "severity",
    "proto": "connection_info.protocol_name",
}

CLASS_META = {
    1006: ("Scheduled Job Activity", 1, "System Activity"),
    1007: ("Process Activity", 1, "System Activity"),
    2004: ("Detection Finding", 2, "Findings"),
    3001: ("Account Change", 3, "Identity & Access Management"),
    3002: ("Authentication", 3, "Identity & Access Management"),
    3003: ("Authorize Session", 3, "Identity & Access Management"),
    3005: ("User Access Management", 3, "Identity & Access Management"),
    4001: ("Network Activity", 4, "Network Activity"),
    4002: ("HTTP Activity", 4, "Network Activity"),
    4003: ("DNS Activity", 4, "Network Activity"),
    4006: ("SMB Activity", 4, "Network Activity"),
    4007: ("SSH Activity", 4, "Network Activity"),
    4009: ("Email Activity", 4, "Network Activity"),
    4012: ("NTP Activity", 4, "Network Activity"),
    5001: ("Device Inventory Info", 5, "Discovery"),
    5002: ("Device Config State", 5, "Discovery"),
    5019: ("Device Config State Change", 5, "Discovery"),
    6002: ("Application Lifecycle", 6, "Application Activity"),
    6003: ("API Activity", 6, "Application Activity"),
    6005: ("Datastore Activity", 6, "Application Activity"),
    6007: ("Scan Activity", 6, "Application Activity"),
}


def mine_json_fingerprints(records: list[dict], min_samples: int, min_purity: float) -> list[dict]:
    """Mine JSON field-set fingerprints that uniquely identify OCSF classes."""
    fingerprints = defaultdict(list)

    for r in records:
        raw = r["raw_log"].strip()
        if not raw.startswith("{"):
            continue
        try:
            d = json.loads(raw)
            if not isinstance(d, dict):
                continue
        except (json.JSONDecodeError, ValueError):
            continue

        keys = sorted(d.keys())[:12]
        fp = "|".join(keys)
        fingerprints[fp].append(r["class_uid"])

    patterns = []
    for fp, classes in fingerprints.items():
        total = len(classes)
        if total < min_samples:
            continue
        dominant = Counter(classes).most_common(1)[0]
        purity = dominant[1] / total
        if purity < min_purity:
            continue

        class_uid = dominant[0]
        keys = fp.split("|")

        # Build field map from known field names
        field_map = {}
        json_has = []
        for key in keys[:6]:  # Use first 6 keys for matching
            json_has.append(key)
            ocsf_path = COMMON_FIELDS_TO_OCSF.get(key)
            if ocsf_path:
                field_map[key] = ocsf_path

        meta = CLASS_META.get(class_uid, ("Unknown", class_uid // 1000, "Unknown"))

        patterns.append({
            "name": f"json_fp_{class_uid}_{abs(hash(fp)) % 10000:04d}",
            "match": {
                "log_format": ["json", "evtx_json"],
                "json_has": json_has[:4],  # First 4 keys for matching
            },
            "ocsf_class_uid": class_uid,
            "ocsf_class_name": meta[0],
            "static": {
                "activity_id": 0,
                "severity_id": 1,
                "category_uid": meta[1],
                "category_name": meta[2],
            },
            "field_map": field_map,
            "_coverage": total,
            "_purity": round(purity, 3),
        })

    return sorted(patterns, key=lambda p: -p["_coverage"])


def main():
    parser = argparse.ArgumentParser(description="Mine patterns from ground truth")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--min-samples", type=int, default=5, help="Min logs per pattern")
    parser.add_argument("--min-purity", type=float, default=0.85, help="Min class purity")
    args = parser.parse_args()

    records = [json.loads(l) for l in open(args.ground_truth)]
    real = [r for r in records if r.get("source") not in ("synthetic", "contrastive", "fleet_generated")]
    print(f"Loaded {len(real)} real records", file=sys.stderr)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Mine JSON fingerprints
    json_patterns = mine_json_fingerprints(real, args.min_samples, args.min_purity)
    total_json_coverage = sum(p["_coverage"] for p in json_patterns)
    print(f"JSON fingerprints: {len(json_patterns)} patterns covering {total_json_coverage} logs", file=sys.stderr)

    # Group by class and write YAML
    by_class = defaultdict(list)
    for p in json_patterns:
        by_class[p["ocsf_class_uid"]].append(p)

    total_patterns = 0
    for class_uid, patterns in sorted(by_class.items()):
        meta = CLASS_META.get(class_uid, ("Unknown", class_uid // 1000, "Unknown"))
        clean_name = meta[0].lower().replace(" ", "_").replace("/", "_")

        yaml_patterns = []
        for p in patterns:
            # Remove internal metadata
            pattern = {k: v for k, v in p.items() if not k.startswith("_")}
            yaml_patterns.append(pattern)

        data = {
            "source": f"mined_{clean_name}",
            "description": f"Auto-mined patterns for {meta[0]} from ground truth",
            "version": 1,
            "auto_generated": True,
            "patterns": yaml_patterns,
        }

        output_file = output_dir / f"mined_{class_uid}_{clean_name}.yaml"
        with open(output_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        total_patterns += len(yaml_patterns)
        print(f"  {class_uid} ({meta[0]}): {len(yaml_patterns)} patterns → {output_file.name}", file=sys.stderr)

    print(f"\nTotal: {total_patterns} mined patterns covering {total_json_coverage} logs", file=sys.stderr)


if __name__ == "__main__":
    main()
