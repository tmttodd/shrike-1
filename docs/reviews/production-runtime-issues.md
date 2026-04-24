# Production Runtime Code Review — Issues Found

**Branch**: `pr/production-runtime` (commit `c96ea67`)
**Review scope**: `runtime.py`, `config.py`, `destinations/`
**Severity**: 🔴 Critical · 🟠 High · 🟡 Medium · ⚠️ Low

---

## 🔴 Critical — Crashes or Data Loss

### 1. `compact()` Race Condition — WAL Corruption Possible

**File**: `shrike/destinations/wal.py`, lines 103–113

```python
async def compact(self) -> None:
    unsent = await self.read_unsent(batch_size=2**31)
    async with aiofiles.open(self._wal_path, "w") as f:   # ← opens for write
        for event in unsent:
            await f.write(json.dumps(event) + "\n")
    async with aiofiles.open(self._cursor_path, "w") as f:
        await f.write("0:0")
```

**Problem**: `compact()` opens the WAL file for write (`"w"`) and rewrites it completely. If the
`DestinationWorker.run()` loop calls `read_unsent()` while `compact()` is mid-write, the read can get
partial lines or corrupted JSON. No file locking or atomic rename.

**Fix**: Write to a temp file, then `os.rename()` atomically to the WAL path. Use `os.replace()`
(Python 3.3+) for atomic rename.

```python
async def compact(self) -> None:
    unsent = await self.read_unsent(batch_size=2**31)
    tmp_path = self._wal_path.with_suffix(".tmp")
    async with aiofiles.open(tmp_path, "w") as f:
        for event in unsent:
            await f.write(json.dumps(event) + "\n")
    os.replace(tmp_path, self._wal_path)
    async with aiofiles.open(self._cursor_path, "w") as f:
        await f.write("0:0")
```

---

### 2. `router.route()` Returns `rejected=len(events)` on WAL Overflow — Semantic Error

**File**: `shrike/destinations/router.py`, lines 33–41

```python
if written == 0:
    results[dest.name] = SendResult(
        accepted=0,
        rejected=len(events),   # ← WRONG: these events weren't "rejected"
        retryable=0,
        errors=["WAL overflow — events dropped"],
    )
```

**Problem**: `rejected` means "permanent rejection (bad data, never retry)" but WAL overflow is
transient capacity. Setting `rejected=len(events)` makes the caller think the data was bad.

**Fix**: Return `accepted=0, rejected=0, retryable=0` on overflow, or use a separate signal.
The `ingest()` caller treats `accepted=0` as WAL-full and returns 507, which is correct — but
the `rejected` count is misleading.

---

## 🟠 High — Functional Bugs

### 3. `ingest()` Returns 507 for Pipeline Drops, Not Just WAL Overflow

**File**: `shrike/runtime.py`, lines 137–140

```python
if total_accepted == 0 and events:
    raise HTTPException(status_code=507, detail="All destinations at capacity")
```

**Problem**: `total_accepted` is the sum of all destinations' WAL writes. If every destination's WAL
is full, this correctly returns 507. But if the pipeline drops all events (e.g., filter pack drops
everything), `events` is empty so the check doesn't fire — that's fine. However, if some events
normalize and some drop, but all WALs are full, the caller can't distinguish "WAL full" from
"pipeline dropped some" from the response.

**Current behavior**: `accepted=0, total=N, normalized=M` where `M > 0` → caller knows WAL is
the bottleneck. But the 507 message says "All destinations at capacity" which is only true when
WALs are full, not when the pipeline drops events.

**Fix**: Return a field that distinguishes the cases:

```python
return {
    "accepted": total_accepted,
    "total": len(body.logs),
    "normalized": len(events),
    "wal_full": total_accepted == 0 and len(events) > 0,
}
# Caller checks wal_full flag instead of accepted==0
```

---

### 4. `compact()` Reads Entire WAL Into Memory — OOM Risk

**File**: `shrike/destinations/wal.py`, line 105

```python
unsent = await self.read_unsent(batch_size=2**31)   # 2**31 ≈ 2 billion
```

**Problem**: If the WAL grows to millions of events, `compact()` loads all unsent events into memory
before rewriting. With a 500MB WAL limit and small events (~1KB each), that's ~500K events in memory.

**Fix**: Compact in chunks, or use a size-based threshold to trigger compaction instead of calling
it after every successful delivery.

```python
async def compact(self, batch_size: int = 10000) -> None:
    unsent = await self.read_unsent(batch_size=batch_size)
    if not unsent:
        return
    async with aiofiles.open(self._wal_path, "w") as f:
        for event in unsent:
            await f.write(json.dumps(event) + "\n")
    # ... reset cursor
```

---

### 5. `verify_auth()` Returns `None` When No Key Configured — Endpoint Is Open

**File**: `shrike/runtime.py`, lines 99–106

```python
async def verify_auth(authorization: str | None = Header(None)):
    if not config.ingest_api_key:
        return    # ← returns None, FastAPI treats this as "pass through"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
```

**Problem**: If `INGEST_API_KEY` is unset/empty, the endpoint accepts any request with no auth. This may be
intentional for internal-only deployments (Caddy handles auth at the proxy layer), but it's not documented and
could be a surprise if someone expects auth to be on by default.

**Fix**: Add an explicit config flag or document the open-by-default behavior.

---

## 🟡 Medium — Operational Issues

### 6. Client IP From `request.client.host` — No Proxy Header Support

**File**: `shrike/runtime.py`, line 130

```python
source_ip = request.client.host if request.client else "unknown"
```

**Problem**: Behind Caddy or any reverse proxy, `request.client.host` is the proxy's IP, not
the real client. `_shrike_source_ip` will always be the proxy IP.

**Fix**: Check `X-Forwarded-For` first:

```python
forwarded = request.headers.get("X-Forwarded-For")
if forwarded:
    source_ip = forwarded.split(",")[0].strip()
else:
    source_ip = request.client.host if request.client else "unknown"
```

---

### 7. `wal_max_mb` Default 500MB — No Size-Based Compaction Trigger

**File**: `shrike/destinations/wal.py`, line 33

```python
self._max_size_bytes = max_size_mb * 1024 * 1024   # 500MB default
```

**Problem**: WAL only compacts when the worker successfully delivers a batch. If Splunk is down for
hours, the WAL grows to 500MB before `append()` starts returning 0. With 500MB of events queued,
a restart could lose them all (WAL is on disk but the cursor is at the end).

**Fix**: Add a periodic size-based compaction even when delivery is failing:

```python
if self._wal_path.stat().st_size >= self._max_size_bytes * 0.8:
    await self.compact()   # compact before overflow
```

---

### 8. `config.mode` in `/health` Response — Not Used

**File**: `shrike/runtime.py`, line 121

```python
return {
    "status": "healthy" if all_healthy else "degraded",
    "mode": config.mode,   # ← returned but never set by runtime
    "pipeline": "active" if _pipeline else "passthrough",
    "destinations": dest_health,
}
```

**Problem**: `config.mode` is always `"full"` (no forwarder mode without OTel). Including it in
the health response is fine for debugging, but it's always the same value.

---

### 9. `DestinationWorker.__init__` Takes `wal` Explicitly — Redundant With `dest.wal`

**File**: `shrike/runtime.py`, line 81

```python
w = DestinationWorker(dest, dest.wal)   # wal passed explicitly
```

**Problem**: `Destination.__init__` sets `self.wal`, so `dest.wal` is always available.
Passing it again is redundant. The worker's `self._wal` and `dest.wal` are the same object.

**Fix**: Remove the explicit `wal` parameter from `DestinationWorker.__init__` and have it
read from `destination.wal` directly.

---

### 10. `ingest()` Endpoint — No Request Body Size Limit Beyond Pydantic

**File**: `shrike/runtime.py`, lines 107–111

```python
class IngestRequest(BaseModel):
    logs: Annotated[
        list[Annotated[str, StringConstraints(max_length=65536)]],
        Field(max_length=10000),
    ]
```

**Problem**: Pydantic validates max_length but doesn't enforce byte size. A request with
10,000 logs of 64KB each is ~640MB — could OOM the server before Pydantic rejects it.

**Fix**: Add a body size limit at the FastAPI level:

```python
from fastapi import Body, FastAPI, Request

app = FastAPI(title="Shrike Runtime", version="0.1.0", lifespan=lifespan,
             limit_max_bytes=10_000_000)   # 10MB max request body
```

---

## ⚠️ Low — Code Quality

### 11. `tempfile` Used in `SplunkHECDestination.__init__` — Not Imported

**File**: `shrike/destinations/splunk_hec.py`, line 76

```python
wal_path = Path(wal_dir) if wal_dir else Path(tempfile.mkdtemp(prefix="shrike-splunk-"))
```

**Problem**: `tempfile` is not in the imports at the top of the file. This will raise
`NameError` at runtime if `wal_dir` is `None`.

**Fix**: Add `import tempfile` at the top of the file.

---

### 12. `aiohttp.ClientSession` Leak on `ensure_indexes()` Exception

**File**: `shrike/destinations/splunk_hec.py`, lines 143–152

```python
try:
    async with session.get(...) as resp:
        ...
        existing = {e["name"] for e in data.get("entry", [])}
except aiohttp.ClientError as exc:
    logger.warning("Index check failed: %s", exc)
    return    # ← session left open
```

**Problem**: If the `async with session.get()` raises an exception after the session is created but
before entering the context manager, the session is not closed. The `_get_session()` method
creates a session lazily, but if it fails mid-creation, there's no cleanup.

**Fix**: Use a context manager for the session in `ensure_indexes()`:

```python
async with aiohttp.ClientSession(...) as session:
    # use session
# session auto-closed
```

---

### 13. `advance_cursor()` Reads Through Events to Compute Offset — O(n) on Batch Size

**File**: `shrike/destinations/wal.py`, lines 85–99

```python
async def advance_cursor(self, count: int) -> None:
    new_byte_offset = byte_offset
    async with aiofiles.open(self._wal_path, "rb") as f:
        await f.seek(byte_offset)
        advanced = 0
        while advanced < count:
            raw_line = await f.readline()
            ...
```

**Problem**: `advance_cursor()` is called after every batch delivery with `count = accepted + rejected`.
For large batches (100 events), this reads through 100 lines to compute the new offset. This is
correct but could be optimized by storing line lengths during `read_unsent()`.

**Fix**: Store line lengths during `read_unsent()` and use them in `advance_cursor()` to skip the
re-read. Low priority.

---

## Summary

| # | Severity | Issue | File | Lines |
|---|---------|-------|------|------|
| 1 | 🔴 Critical | `compact()` race — WAL corruption | wal.py | 103–113 |
| 2 | 🔴 Critical | `rejected=len(events)` on overflow | router.py | 33–41 |
| 3 | 🟠 High | 507 for WAL overflow vs pipeline drop | runtime.py | 137–140 |
| 4 | 🟠 High | `compact()` OOM on large WAL | wal.py | 105 |
| 5 | 🟠 High | Open endpoint when no API key | runtime.py | 99–106 |
| 6 | 🟡 Medium | No `X-Forwarded-For` support | runtime.py | 130 |
| 7 | 🟡 Medium | No size-based compaction trigger | wal.py | 33 |
| 8 | 🟡 Medium | `config.mode` unused in runtime | runtime.py | 121 |
| 9 | 🟡 Medium | Redundant `wal` param in worker | runtime.py | 81 |
| 10 | 🟡 Medium | No request body byte limit | runtime.py | 107–111 |
| 11 | ⚠️ Low | `tempfile` not imported | splunk_hec.py | 76 |
| 12 | ⚠️ Low | Session leak on index check error | splunk_hec.py | 143–152 |
| 13 | ⚠️ Low | `advance_cursor()` O(n) re-read | wal.py | 85–99 |

**Recommended order**: Fix #1 and #2 first (data integrity). Then #11 (crash), #4 (OOM), #3
(functional correctness), #5 (security posture).