#!/usr/bin/env python3
"""rsyslog FIFO forwarder — reads syslog from FIFO, POSTs to Shrike HTTP API.

Run as:  python -m shrike.collector.rsyslog_forwarder --fifo /var/run/shrike-fifo --shrike-url http://localhost:8080

rsyslog config:
  module(load="imuxsock")
  module(load="omfwd")
  action(type="omfwd" Target="127.0.0.1" Port="1515" Protocol="tcp")
  *.* action(type="omfwd" File="/var/run/shrike-fifo")
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import select
import signal
import socket
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="rsyslog FIFO forwarder to Shrike HTTP")
    parser.add_argument("--fifo", default="/var/run/shrike-fifo", help="FIFO path to read from")
    parser.add_argument("--shrike-url", default="http://localhost:8080", help="Shrike base URL")
    parser.add_argument("--batch-size", type=int, default=50, help="Max batch size")
    parser.add_argument("--batch-interval", type=float, default=2.0, help="Max wait before flush (s)")
    parser.add_argument("--api-key", default="", help="Shrike API key (optional)")
    return parser.parse_args()


class FIFOReader:
    """Non-blocking FIFO reader with batched HTTP forwarding."""

    def __init__(self, fifo_path: str, shrike_url: str, batch_size: int, batch_interval: float, api_key: str):
        self.fifo_path = Path(fifo_path)
        self.shrike_url = shrike_url.rstrip("/")
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.api_key = api_key
        self._buffer: list[str] = []
        self._last_send = time.monotonic()
        self._running = False

    def _create_fifo(self):
        os.mkfifo(self.fifo_path) if not self.fifo_path.exists() else None
        Path(self.fifo_path).touch()

    def _send_batch(self, logs: list[str]) -> bool:
        import urllib.request
        payload = json.dumps({"logs": logs}).encode()
        req = urllib.request.Request(
            f"{self.shrike_url}/v1/ingest",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        if self.api_key:
            req.add_header("X-API-Key", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _flush(self):
        if not self._buffer:
            return
        logs = self._buffer[:]
        self._buffer.clear()
        ok = self._send_batch(logs)
        if not ok:
            self._buffer = logs + self._buffer  # prepend on failure
            print(f"Failed to send {len(logs)} logs, will retry", flush=True)

    def run(self):
        self._running = True
        # Create FIFO if it doesn't exist
        if not self.fifo_path.exists():
            os.mkfifo(self.fifo_path)
        fd = os.open(self.fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        buf = b""

        print(f"Reading from FIFO {self.fifo_path} -> {self.shrike_url}", flush=True)

        try:
            while self._running:
                # Check for flush timeout
                if self._buffer and (time.monotonic() - self._last_send) >= self.batch_interval:
                    self._flush()
                    self._last_send = time.monotonic()

                # Read from FIFO (non-blocking)
                try:
                    chunk = os.read(fd, 8192)
                    if chunk:
                        buf += chunk
                except BlockingIOError:
                    pass

                # Process complete lines
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        raw = line.decode("utf-8", errors="replace").strip()
                    except Exception:
                        continue
                    if not raw or len(raw) < 4:
                        continue
                    self._buffer.append(raw)
                    self._last_send = time.monotonic()
                    if len(self._buffer) >= self.batch_size:
                        self._flush()
                        self._last_send = time.monotonic()

                # Brief sleep to avoid busy loop
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        finally:
            os.close(fd)
            self._flush()
            print("Stopped", flush=True)


def main():
    args = parse_args()
    reader = FIFOReader(
        fifo_path=args.fifo,
        shrike_url=args.shrike_url,
        batch_size=args.batch_size,
        batch_interval=args.batch_interval,
        api_key=args.api_key,
    )
    reader.run()


if __name__ == "__main__":
    main()