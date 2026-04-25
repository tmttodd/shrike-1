"""Prometheus metrics for Shrike runtime."""

from prometheus_client import Counter, Gauge, Histogram

events_accepted = Counter("shrike_events_accepted", "Events accepted", ["dest"])
events_rejected = Counter("shrike_events_rejected", "Events rejected", ["dest"])
events_normalized = Counter("shrike_events_normalized", "Events normalized")
wal_pending = Gauge("shrike_wal_pending", "Pending events in WAL", ["dest"])
wal_disk_mb = Gauge("shrike_wal_disk_mb", "WAL disk MB", ["dest"])
dest_health = Gauge("shrike_dest_health", "Dest health", ["dest"])
request_duration_ms = Histogram("shrike_request_duration_ms", "Request duration ms", ["endpoint"])