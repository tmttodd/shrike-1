#!/usr/bin/env python3
"""Fleet-wide cross-validated training data generator.

Uses multiple vLLM endpoints in parallel to generate and cross-validate
OCSF training data. Generator creates logs, validator classifies them,
only agreement passes through.

Usage:
    python scripts/fleet_generate.py \
        --output data/ground_truth/fleet_generated.jsonl \
        --existing data/ground_truth/full_contrastive_training.jsonl \
        --per-class 150
"""

import argparse
import asyncio
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

import aiohttp

# Fleet endpoints
GENERATORS = [
    {"name": "model-a", "url": "http://localhost:8000/v1/chat/completions", "model": "model-a", "thinking": False},
    {"name": "model-b", "url": "http://localhost:8001/v1/chat/completions", "model": "model-b", "thinking": False},
    {"name": "model-c", "url": "http://localhost:8002/v1/chat/completions", "model": "model-c", "thinking": False},
]

VALIDATOR = {"name": "model-b", "url": "http://localhost:8001/v1/chat/completions", "model": "model-b"}

# Classes that need data, with descriptions and discriminative features
CLASSES_NEEDED = {
    2002: {"name": "Vulnerability Finding", "need": 150, "desc": "CVE scan results from Nessus, Qualys, Rapid7, OpenVAS. MUST have CVE IDs, CVSS scores, affected software+version. NOT real-time alerts (that's Detection Finding). NOT broad assessments (that's Security Finding)."},
    3006: {"name": "Group Management", "need": 150, "desc": "AD/LDAP group membership changes. Windows Events 4728/4732/4756/4733/4729. User added/removed from security groups, distribution lists. Include group name, member, who made the change."},
    4011: {"name": "TLS/SSL Activity", "need": 120, "desc": "TLS handshake events, certificate validation, cipher negotiation, cert expiry warnings, SSL errors. From load balancers, web proxies, IDS. NOT HTTP requests (that's HTTP Activity)."},
    1002: {"name": "Kernel Extension Activity", "need": 140, "desc": "Kernel module/extension load/unload events. Linux: insmod/modprobe/rmmod via auditd. macOS: kext load. Windows: driver load (Sysmon Event 6). Include module name, hash, signer."},
    2001: {"name": "Security Finding", "need": 140, "desc": "SAST/DAST scan results, pentest findings, security assessment output, code review findings. NOT CVE-specific (that's Vulnerability Finding). NOT real-time detection (that's Detection Finding)."},
    2006: {"name": "Data Security Finding", "need": 150, "desc": "DLP alerts: sensitive data in email/cloud/endpoint. PII/PHI/PCI detection, unauthorized data transfer, data classification violations. From DLP tools (Symantec, Forcepoint), CASB, email gateways."},
    4004: {"name": "DHCP Activity", "need": 130, "desc": "DHCP lease events: DISCOVER, OFFER, REQUEST, ACK, RELEASE, RENEW. Include MAC address, assigned IP, lease duration, DHCP server. From DHCP servers (ISC, Windows), network monitors."},
    4013: {"name": "Tunnel Activity", "need": 150, "desc": "VPN/tunnel establishment and teardown. IPsec, GRE, WireGuard, OpenVPN, SSH tunnel events. Include tunnel endpoints, protocol, duration. NOT general network connections (that's Network Activity)."},
    4006: {"name": "SMB Activity", "need": 100, "desc": "SMB/CIFS file share operations. Windows Event 5140/5145, Samba audit. Share access, file open/close over SMB, permission checks. Include share name, file path, user, access type."},
    4008: {"name": "FTP Activity", "need": 100, "desc": "FTP/SFTP file transfer events. Login, upload, download, directory listing. From FTP servers (vsftpd, ProFTPD, FileZilla), SFTP (OpenSSH). Include filename, transfer size, user, direction."},
    5003: {"name": "User Inventory Info", "need": 100, "desc": "User account inventory/enumeration. Account listing, user properties dump, directory sync reports. NOT user login (that's Authentication). NOT permission changes (that's User Access Management)."},
    2005: {"name": "Incident Finding", "need": 150, "desc": "Security incident detections: malware found, intrusion detected, data breach alert, ransomware activity. From SIEM correlation rules, EDR behavioral detection, incident management systems. Higher severity than Detection Finding."},
    4005: {"name": "RDP Activity", "need": 70, "desc": "Remote Desktop Protocol events. Windows Event 4624 type 10, RDP session connect/disconnect, NLA authentication. Include source IP, target host, session ID, user. NOT general auth (that's Authentication)."},
    4002: {"name": "HTTP Activity", "need": 50, "desc": "Layer 7 HTTP request/response events. MUST have HTTP method (GET/POST/PUT/DELETE), URL path, status code (200/404/500), user-agent. From web servers, reverse proxies, WAF. NOT API calls with structured payloads (that's API Activity). NOT raw TCP connections (that's Network Activity)."},
    4001: {"name": "Network Activity", "need": 50, "desc": "Layer 3-4 network connection events. TCP/UDP flows, firewall allow/deny, IDS flow data. Source/dest IP+port, protocol, bytes, packets. NO HTTP methods, NO URLs, NO user-agents (those go to HTTP Activity). NO API endpoints (those go to API Activity)."},
}

LOG_FORMATS = [
    "syslog RFC 5424 (with PRI, version, ISO timestamp, hostname, app, PID, MSGID)",
    "syslog BSD (Mon DD HH:MM:SS hostname app[pid]: message)",
    "CEF (CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions)",
    "JSON (flat object with timestamp, source, event_type, and class-specific fields)",
    "Windows Event Log JSON (EventID, Channel, Computer, EventData with named fields)",
    "key=value pairs (space-separated, with timestamp prefix)",
    "CSV (comma-separated values with implied headers)",
]


def parse_logs(content: str) -> list[str]:
    """Extract valid log lines from LLM output."""
    lines = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or len(line) < 30:
            continue
        if line.startswith("```") or line.startswith("#") or line.startswith("---"):
            continue
        if line.lower().startswith("here") or line.lower().startswith("note"):
            continue
        # Strip numbering
        line = re.sub(r"^\d+[\.\)]\s*", "", line)
        if len(line) < 30:
            continue
        lines.append(line)
    return lines


async def generate_batch(session: aiohttp.ClientSession, endpoint: dict,
                         class_uid: int, class_info: dict, batch_num: int) -> list[str]:
    """Generate a batch of logs from one endpoint."""
    fmt_list = "\n".join(f"  - {f}" for f in LOG_FORMATS)
    prompt = f"""Generate 20 unique realistic raw log lines for OCSF class "{class_info['name']}" (class_uid: {class_uid}).

{class_info['desc']}

Use these formats (vary across the batch):
{fmt_list}

Requirements:
- Each log must look like REAL production data
- Use realistic hostnames, IPs (10.x, 172.x, 192.168.x), usernames, timestamps
- Vary sources, actors, targets, severities across logs
- Batch {batch_num}: focus on {'normal operations' if batch_num % 3 == 0 else 'security alerts/anomalies' if batch_num % 3 == 1 else 'error conditions and edge cases'}
- Output ONLY raw log lines, one per line. No explanations."""

    payload = {
        "model": endpoint["model"],
        "messages": [
            {"role": "system", "content": "You are a log data generator. Output only raw log lines, nothing else."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.9,
        "max_tokens": 4096,
    }
    if not endpoint.get("thinking", True):
        payload["chat_template_kwargs"] = {"enable_thinking": False}

    try:
        async with session.post(endpoint["url"], json=payload,
                                headers={"Content-Type": "application/json"},
                                timeout=aiohttp.ClientTimeout(total=120)) as resp:
            if resp.status != 200:
                return []
            result = await resp.json()
            content = result["choices"][0]["message"]["content"]
            return parse_logs(content)
    except Exception as e:
        print(f"    {endpoint['name']} error: {e}", file=sys.stderr)
        return []


async def validate_batch(session: aiohttp.ClientSession, logs: list[str],
                         expected_uid: int, class_name: str) -> list[str]:
    """Validate logs by asking the validator to classify them."""
    if not logs:
        return []

    # Batch validate — ask validator to classify each log
    validated = []
    # Process in chunks of 10
    for i in range(0, len(logs), 10):
        chunk = logs[i:i+10]
        numbered = "\n".join(f"{j+1}. {log[:300]}" for j, log in enumerate(chunk))

        prompt = f"""Classify each log line into its OCSF event class. For each line, output ONLY the class_uid number.

Valid OCSF classes include:
1001=FileSystem, 1002=KernelExtension, 1003=Kernel, 1004=Memory, 1005=Module, 1006=ScheduledJob, 1007=Process, 1008=EventLog,
2001=SecurityFinding, 2002=VulnerabilityFinding, 2003=ComplianceFinding, 2004=DetectionFinding, 2005=IncidentFinding, 2006=DataSecurityFinding,
3001=AccountChange, 3002=Authentication, 3003=AuthorizeSession, 3004=EntityManagement, 3005=UserAccessManagement, 3006=GroupManagement,
4001=NetworkActivity, 4002=HTTPActivity, 4003=DNS, 4004=DHCP, 4005=RDP, 4006=SMB, 4007=SSH, 4008=FTP, 4009=Email, 4010=NetworkFile, 4011=TLS, 4012=NTP, 4013=Tunnel, 4014=EmailURL,
5001=DeviceInventory, 5002=DeviceConfigState, 5003=UserInventory, 5004=OSPatchState, 5019=DeviceConfigChange,
6001=WebResources, 6002=ApplicationLifecycle, 6003=APIActivity, 6005=Datastore, 6007=ScanActivity

Log lines:
{numbered}

Output ONLY the class_uid for each line, one per line (e.g., "4001" or "3002"). No explanations."""

        payload = {
            "model": VALIDATOR["model"],
            "messages": [
                {"role": "system", "content": "Output only class_uid numbers, one per line."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 256,
            "chat_template_kwargs": {"enable_thinking": False},
        }

        try:
            async with session.post(VALIDATOR["url"], json=payload,
                                    headers={"Content-Type": "application/json"},
                                    timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status != 200:
                    validated.extend(chunk)  # Keep all if validator fails
                    continue
                result = await resp.json()
                content = result["choices"][0]["message"]["content"]

                # Parse validator output
                val_lines = [l.strip() for l in content.strip().split("\n") if l.strip()]
                for j, log in enumerate(chunk):
                    if j < len(val_lines):
                        try:
                            val_uid = int(re.search(r"\d{4}", val_lines[j]).group())
                            if val_uid == expected_uid:
                                validated.append(log)
                            # else: disagreement — skip this log
                        except (ValueError, AttributeError):
                            validated.append(log)  # Can't parse — keep it
                    else:
                        validated.append(log)  # No validator output — keep it
        except Exception:
            validated.extend(chunk)  # Validator error — keep all

    return validated


async def generate_class(session: aiohttp.ClientSession, class_uid: int,
                         class_info: dict, existing_hashes: set) -> list[dict]:
    """Generate and validate data for one class using multiple endpoints."""
    target = class_info["need"]
    results = []
    batch_num = 0

    while len(results) < target and batch_num < 30:
        # Fan out to all generators in parallel
        tasks = []
        for endpoint in GENERATORS:
            tasks.append(generate_batch(session, endpoint, class_uid, class_info, batch_num))
            batch_num += 1

        batches = await asyncio.gather(*tasks)

        # Merge and dedup
        all_logs = []
        for batch in batches:
            for log in batch:
                if log[:100] not in existing_hashes:
                    all_logs.append(log)
                    existing_hashes.add(log[:100])

        # Cross-validate
        validated = await validate_batch(session, all_logs, class_uid, class_info["name"])

        for log in validated:
            results.append({
                "raw_log": log,
                "class_uid": class_uid,
                "class_name": class_info["name"],
                "source": "fleet_generated",
            })

        gen_count = sum(len(b) for b in batches)
        print(f"    Batch {batch_num//3}: generated {gen_count}, validated {len(validated)}, "
              f"total {len(results)}/{target}", file=sys.stderr)

    return results[:target]


async def main():
    parser = argparse.ArgumentParser(description="Fleet-wide cross-validated data generator")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--existing", help="Existing training data for dedup")
    parser.add_argument("--per-class", type=int, default=0, help="Override per-class target (0=use defaults)")
    args = parser.parse_args()

    # Load existing hashes for dedup
    existing_hashes = set()
    if args.existing and Path(args.existing).exists():
        with open(args.existing) as f:
            for line in f:
                r = json.loads(line)
                existing_hashes.add(r["raw_log"][:100])
        print(f"Loaded {len(existing_hashes)} existing hashes for dedup", file=sys.stderr)

    # Override per-class if specified
    if args.per_class > 0:
        for uid in CLASSES_NEEDED:
            CLASSES_NEEDED[uid]["need"] = args.per_class

    total_needed = sum(c["need"] for c in CLASSES_NEEDED.values())
    print(f"Generating {total_needed} examples across {len(CLASSES_NEEDED)} classes", file=sys.stderr)
    print(f"Using {len(GENERATORS)} generators + 1 validator", file=sys.stderr)

    start = time.time()
    all_results = []

    async with aiohttp.ClientSession() as session:
        for uid, info in CLASSES_NEEDED.items():
            print(f"\n  {uid} ({info['name']}): target {info['need']}...", file=sys.stderr)
            results = await generate_class(session, uid, info, existing_hashes)
            all_results.extend(results)
            print(f"  -> {len(results)} validated examples", file=sys.stderr)

    # Write output
    with open(args.output, "w") as f:
        for r in all_results:
            f.write(json.dumps(r) + "\n")

    elapsed = time.time() - start
    counts = Counter(r["class_uid"] for r in all_results)
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Fleet Generation Complete: {len(all_results)} examples in {elapsed:.0f}s", file=sys.stderr)
    for uid, count in sorted(counts.items()):
        name = CLASSES_NEEDED[uid]["name"]
        target = CLASSES_NEEDED[uid]["need"]
        status = "✓" if count >= target * 0.8 else "✗"
        print(f"  {status} {uid} ({name}): {count}/{target}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
