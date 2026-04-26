#!/usr/bin/env python3
"""rsyslog omprog forwarder — reads syslog lines from stdin, POSTs to Shrike HTTP API.

rsyslog config (drop-in for /etc/rsyslog.d/shrike.conf):
    module(load="ompprog")
    action(type="ompprog" binary="/usr/local/bin/rsyslog-stdin-forwarder --shrike-url http://shrike:8080")

No extra rsyslog modules needed. Python stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request


def parse_args() -> list[str]:
    args = []
    for arg in sys.argv[1:]:
        if arg.startswith("--"):
            if "=" in arg:
                key, val = arg.split("=", 1)
                args.append((key, val))
            else:
                args.append((arg, None))
    return args


def main():
    shrike_url = "http://localhost:8080"
    api_key = os.environ.get("SHRIKE_INGEST_API_KEY", "")

    for arg in sys.argv[1:]:
        if arg.startswith("--shrike-url="):
            shrike_url = arg.split("=", 1)[1]
        elif arg == "--shrike-url" and len(sys.argv) > 2:
            shrike_url = sys.argv[2]
            sys.argv = sys.argv[1:]

    shrike_url = shrike_url.rstrip("/")

    batch = []
    batch_size = 50

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        raw = line.strip()
        if not raw or len(raw) < 4:
            continue
        batch.append(raw)
        if len(batch) >= batch_size:
            send_batch(shrike_url, batch, api_key)
            batch = []

    if batch:
        send_batch(shrike_url, batch, api_key)


def send_batch(url: str, logs: list[str], api_key: str):
    payload = json.dumps({"logs": logs}).encode()
    req = urllib.request.Request(
        f"{url}/v1/ingest",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    if api_key:
        req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                print(f"Shrike returned {resp.status}", file=sys.stderr)
    except Exception as e:
        print(f"Failed to send to Shrike: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()