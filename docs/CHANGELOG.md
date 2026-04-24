# Changelog

## [0.1.0] — 2026-04-24

### Features
- (none yet)

### Fixes
- WAL overflow: rejected count now 0 instead of len(events) preventing cursor corruption
- Compact race: atomic os.replace() + cursor update after WAL write
- WAL concurrent access: asyncio.Lock() on all WAL operations
- fsync after every WAL write to survive crashes
- Graceful 30s drain on SIGTERM
- Compact memory: chunked reading, skip WALs under 50MB
- Compact trigger: proactive at 80% capacity
- X-Forwarded-For: respects proxy header in /v1/ingest
- 507 vs 400: WAL full returns 507, data rejected returns 400
- BodySizeLimitMiddleware: 10MB byte limit returns 413
- Config.validate(): raises ValueError on invalid config (fail-fast)
- Auth: hmac.compare_digest with bytes encoding
- WAL advance_cursor: stores line lengths to skip O(n) re-read

### Changes
- Splunk HEC default index: ocsf-raw (was main)
- /health: removed 'mode' field (always 'full')
- WAL wal param: now optional in DestinationWorker

### Tests
- 507 WAL full test
- Partial success test (200 with accepted=N)
- WAL compact memory bounds test
- WAL concurrent read+compact test
- WAL atomic cursor update test
- WAL skip small WAL test
- WAL 80% auto-compact test
- Body 413 test
- Config validate raises ValueError tests
- Splunk HEC mock session.get() for ensure_indexes()
