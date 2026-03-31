#!/usr/bin/env python3
"""Generate synthetic log data for underrepresented OCSF classes.

Uses a teacher LLM to generate realistic raw log lines for specific
OCSF classes. Each log must look like real data from a real source.

Usage:
    python scripts/generate_synthetic.py \
        --classes 2002,2003,2005,3006,4005,6001 \
        --per-class 100 \
        --output data/ground_truth/synthetic_weak_classes.jsonl \
        --api-base http://litellm:4000/v1 \
        --model reason-medium
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

# OCSF class descriptions for prompting
OCSF_CLASS_INFO = {
    1004: ("Memory Activity", "Memory access, allocation, or manipulation events. Examples: buffer overflow detection, memory-mapped file access, heap spray detection."),
    1005: ("Module Activity", "Module/library loading events. Examples: DLL loads, kernel module insertion, shared library loads. Sources: Sysmon Event 7, auditd, EDR."),
    2001: ("Security Finding", "Security findings from scanning tools. Examples: vulnerability scan results, security assessment findings, penetration test discoveries."),
    2002: ("Vulnerability Finding", "Vulnerability discoveries in systems/software. Examples: CVE findings, patch missing alerts, configuration weaknesses. Sources: Nessus, Qualys, Rapid7."),
    2003: ("Compliance Finding", "Compliance check results. Examples: CIS benchmark failures, PCI-DSS violations, HIPAA compliance gaps. Sources: compliance scanners, audit tools."),
    2005: ("Incident Finding", "Security incident detections. Examples: malware detection, intrusion alerts, data exfiltration detection. Sources: SIEM, EDR, IDS/IPS."),
    2006: ("Data Security Finding", "Data security/DLP events. Examples: sensitive data exposure, unauthorized data transfer, PII detection. Sources: DLP tools, CASB."),
    3006: ("Group Management", "Group membership changes. Examples: user added to admin group, security group modified, distribution list changes. Sources: Active Directory, LDAP, IAM."),
    4005: ("RDP Activity", "Remote Desktop Protocol events. Examples: RDP connection established/terminated, RDP authentication. Sources: Windows Event Log, network monitors."),
    4010: ("Network File Activity", "Network file operations. Examples: SMB file access, NFS operations, CIFS share access. Sources: file servers, NAS, network monitors."),
    4011: ("TLS/SSL Activity", "TLS/SSL handshake and certificate events. Examples: certificate validation, cipher negotiation, TLS errors. Sources: web proxies, load balancers, IDS."),
    4014: ("Email URL Activity", "URL activity within emails. Examples: clicked URLs in emails, URL reputation checks, phishing URL detection. Sources: email gateways, URL sandboxes."),
    5002: ("Device Config State", "Device configuration state snapshots. Examples: running config dumps, firmware versions, interface states. Sources: network devices, SNMP, config management."),
    5019: ("Device Config State Change", "Device configuration changes. Examples: config modifications, firmware updates, policy changes. Sources: network devices, change management, SNMP traps."),
    6001: ("Web Resources Activity", "Web resource access events. Examples: HTTP requests to APIs, web scraping, CDN access. Sources: WAF, reverse proxies, CDN logs."),
    6007: ("Scan Activity", "Network or host scanning events. Examples: port scans, vulnerability scans, service discovery. Sources: IDS/IPS, firewall, network monitors."),
}

LOG_FORMATS = [
    "syslog (RFC 5424 with PRI, timestamp, hostname, app, PID)",
    "syslog (BSD format: Mon DD HH:MM:SS hostname app[pid]: message)",
    "CEF (CEF:0|Vendor|Product|Version|EventID|Name|Severity|key=value pairs)",
    "JSON (flat object with timestamp, source, message, and relevant fields)",
    "Windows Event Log JSON (EventID, Channel, Computer, Description, EventData)",
    "key=value pairs (space-separated key=value format)",
    "CSV (comma-separated with header-implied fields)",
]


def generate_batch(api_base: str, model: str, api_key: str, class_uid: int, class_name: str, description: str, count: int, existing_samples: list[str]) -> list[dict]:
    """Generate a batch of synthetic logs for one class."""
    import urllib.request

    # Pick format variety
    format_examples = "\n".join(f"  - {f}" for f in LOG_FORMATS)

    # Show some existing examples if available
    example_section = ""
    if existing_samples:
        examples = existing_samples[:3]
        example_section = "\n\nExisting examples for reference (generate DIFFERENT ones):\n" + "\n".join(f"  {e[:200]}" for e in examples)

    prompt = f"""Generate exactly {count} realistic raw log lines for the OCSF class "{class_name}" (class_uid: {class_uid}).

Description: {description}

Requirements:
1. Each log must look like REAL raw data from a real security product or system
2. Use a VARIETY of log formats across the batch:
{format_examples}
3. Use realistic hostnames, IPs (10.x, 172.x, 192.168.x), usernames, timestamps
4. Each log must be on its own line
5. NO explanations, NO numbering, NO blank lines — ONLY raw log lines
6. Make each log unique — vary sources, actors, targets, actions, severities
7. Include both normal and anomalous/alert events
{example_section}

Output ONLY the raw log lines, one per line:"""

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a log data generator. Output only raw log lines, nothing else."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.8,
        "max_tokens": 8192,
    }).encode()

    req = urllib.request.Request(
        f"{api_base}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read())
        content = result["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  API error: {e}", file=sys.stderr)
        return []

    # Parse lines
    records = []
    for line in content.strip().split("\n"):
        line = line.strip()
        # Skip empty, numbered, or explanation lines
        if not line or len(line) < 20:
            continue
        if re.match(r"^\d+[\.\)]\s", line):
            line = re.sub(r"^\d+[\.\)]\s*", "", line)
        if line.startswith("```") or line.startswith("#") or line.startswith("Here"):
            continue

        records.append({
            "raw_log": line,
            "class_uid": class_uid,
            "class_name": class_name,
            "source": "synthetic",
        })

    return records


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic log data")
    parser.add_argument("--classes", required=True, help="Comma-separated class UIDs")
    parser.add_argument("--per-class", type=int, default=100, help="Logs per class")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--api-base", default="http://litellm:4000/v1")
    parser.add_argument("--model", default="reason-medium")
    parser.add_argument("--api-key", default="not-needed")
    parser.add_argument("--existing", help="Existing ground truth JSONL (for dedup/reference)")
    args = parser.parse_args()

    class_uids = [int(x) for x in args.classes.split(",")]

    # Load existing samples for reference
    existing_by_class: dict[int, list[str]] = {}
    if args.existing and Path(args.existing).exists():
        with open(args.existing) as f:
            for line in f:
                r = json.loads(line)
                uid = r["class_uid"]
                if uid in class_uids:
                    existing_by_class.setdefault(uid, []).append(r["raw_log"])

    total_generated = 0

    with open(args.output, "w") as out:
        for uid in class_uids:
            info = OCSF_CLASS_INFO.get(uid)
            if info is None:
                print(f"Skipping unknown class {uid}", file=sys.stderr)
                continue

            class_name, description = info
            existing = existing_by_class.get(uid, [])
            print(f"Generating {args.per_class} logs for {uid} ({class_name})...", file=sys.stderr)

            # Generate in small batches for reliability
            generated = []
            batch_size = 15
            attempts = 0
            max_attempts = 20

            while len(generated) < args.per_class and attempts < max_attempts:
                needed = min(batch_size, args.per_class - len(generated))
                batch = generate_batch(
                    args.api_base, args.model, args.api_key,
                    uid, class_name, description, needed,
                    existing + [r["raw_log"] for r in generated[-5:]],
                )
                generated.extend(batch)
                attempts += 1
                print(f"  Batch {attempts}: got {len(batch)}, total {len(generated)}/{args.per_class}", file=sys.stderr)

            # Write
            for r in generated[:args.per_class]:
                out.write(json.dumps(r) + "\n")

            total_generated += min(len(generated), args.per_class)
            print(f"  -> {min(len(generated), args.per_class)} written", file=sys.stderr)

    print(f"\nTotal: {total_generated} synthetic logs written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
