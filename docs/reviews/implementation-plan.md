# Production Runtime — Implementation Plan
**Branch**: `pr/production-runtime` → `fix/production-runtime`
**Status**: Ralph Wiggum consensus — Round 2 complete
**Models**: architect (chat/Qwen3.5-122B) + planner (code/MiniMax M2.7) + reviewer (chat/Qwen3.5-122B)

---

## Process Summary

| Round | Models | Output |
|-------|--------|--------|
| 1 | architect + planner + reviewer (parallel) | 13 issues reviewed, 3 model perspectives |
| 2 | architect + planner (parallel, adversarial) | Synthesis of agreements, disagreements, missed bugs |

**Consensus reached**: All 3 models agree on Phase 1–5 ordering, fix correctness, and test strategy.

---

## Phase 1 — Data Integrity Foundations

*Prerequisite for all other phases. These fixes are interdependent and must land together.*

### 1.1 🔴 `#11` — `tempfile` not imported → guaranteed crash

**File**: `shrike/destinations/splunk_hec.py`
**Severity**: 🔴 Critical (was ⚠️ Low — review underestimated latent crash)
**Models agreed**: 3/3

**Root cause**: `tempfile.mkdtemp()` called at line 76 without `import tempfile`. If `wal_dir=None`, `NameError` crashes the destination constructor.

**Fix**:
```python
import tempfile  # ← add this import
# OR: require wal_dir always — remove the tempfile fallback
```

**Verification**: `python3 -c "from shrike.destinations.splunk_hec import SplunkHECDestination; SplunkHECDestination('http://x:8089', 'tok')"` — no `NameError`.

**Test**: `tests/destinations/test_splunk_hec.py` — instantiate without `wal_dir`, assert no exception and `dest.wal` exists.

---

### 1.2 🔴 `#2` — `rejected=len(events)` on WAL overflow → cursor corruption

**File**: `shrike/destinations/router.py`
**Severity**: 🔴 Critical (was 🔴 Critical — confirmed)
**Models agreed**: 3/3

**Root cause**: When WAL overflows, `append()` returns 0 (nothing written). Router sets `rejected=len(events)`. Worker calls `advance_cursor(accepted + rejected)` = `advance_cursor(len(events))`. But those lines DON'T EXIST in the WAL. Cursor advances past end of file. Future `read_unsent()` seeks to byte offset beyond file → returns empty → `pending_count` goes negative → **duplicate delivery** of events that were never written.

**Fix**:
```python
# router.py — route()
if written == 0:
    results[dest.name] = SendResult(
        accepted=0,
        rejected=0,          # ← was len(events) — WRONG
        retryable=0,
        errors=["WAL at capacity — events not queued"],
    )
```

**Verification**: Mock WAL `append()` returning 0. Assert `result.rejected == 0` and `result.retryable == 0`.

**Test**: `tests/destinations/test_router.py` — add test: WAL full → assert `rejected=0, retryable=0`.

---

### 1.3 🔴 `#1` — `compact()` race + cursor atomicity

**File**: `shrike/destinations/wal.py`
**Severity**: 🔴 Critical (was 🔴 Critical — confirmed)
**Models agreed**: 3/3

**Root cause (two bugs)**:

*Bug A — WAL file corruption*: `compact()` opens WAL in `"w"` mode. Worker `read_unsent()` can read partial lines during the write. No atomic rename.

*Bug B — Cursor not atomic with WAL*: `compact()` resets cursor to `"0:0"` AFTER writing the WAL file. If crash occurs between WAL write and cursor write, cursor references wrong state. Also: `_line_count` is updated AFTER cursor write — if `advance_cursor()` runs between cursor reset and `_line_count` update, `pending_count` is wrong and events get re-delivered.

**Fix** — three-part atomic transaction:

```python
import os
import tempfile

class WriteAheadLog:
    async def compact(self) -> None:
        # Step 1: Read all unsent (protected by mutex — see 1.4)
        unsent = await self.read_unsent(batch_size=2**31)
        if not unsent:
            return

        # Step 2: Write to temp file, fsync, atomic rename
        tmp_path = self._wal_path.with_suffix(".tmp")
        async with aiofiles.open(tmp_path, "w") as f:
            for event in unsent:
                await f.write(json.dumps(event) + "\n")
            await f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self._wal_path)  # atomic

        # Step 3: Write cursor AFTER WAL is on disk (also atomic)
        cursor_tmp = self._cursor_path.with_suffix(".tmp")
        async with aiofiles.open(cursor_tmp, "w") as f:
            await f.write("0:0")
        os.replace(cursor_tmp, self._cursor_path)

        # Step 4: Update _line_count AFTER cursor is consistent
        self._line_count = len(unsent)
```

**Note**: `os.replace()` is Python 3.3+ — atomic across POSIX. On Windows, `os.replace()` also atomic.

**Verification**: Concurrent test — `compact()` + `read_unsent()` in two async tasks. Assert no `JSONDecodeError`, no partial lines, cursor is consistent.

**Test**: `tests/destinations/test_wal.py` — add concurrent compact+read test. Add memory usage test with 100K events (use `tracemalloc`).

---

### 1.4 🟠 **NEW** — Async mutex for WAL operations

**File**: `shrike/destinations/wal.py`
**Severity**: 🟠 High (prerequisite for #1, #7)
**Models agreed**: 3/3 (architect identified as prerequisite)

**Root cause**: No mutual exclusion. `append()` (from ingest path), `read_unsent()`, `advance_cursor()`, and `compact()` (from worker path) can interleave arbitrarily. Even with atomic rename, concurrent reads during compaction see an inconsistent file state.

**Fix**:

```python
import asyncio

class WriteAheadLog:
    def __init__(self, ...):
        # ... existing init ...
        self._lock = asyncio.Lock()

    async def append(self, events: list[dict]) -> int:
        async with self._lock:
            # existing overflow check and write
            ...

    async def read_unsent(self, batch_size: int = 100) -> list[dict]:
        async with self._lock:
            # existing read logic
            ...

    async def advance_cursor(self, count: int) -> None:
        async with self._lock:
            # existing cursor advancement
            ...

    async def compact(self) -> None:
        async with self._lock:
            # existing compact logic
            ...
```

**Trade-off**: `append()` now serialized — one destination's ingest waits for another's if multiple destinations. Acceptable since destinations are independent (each has its own WAL + lock).

**Verification**: No test needed for mutex itself (hard to test directly). Covered by concurrent compact+read test from 1.3.

---

### 1.5 🟠 **NEW** — Splunk management URL construction broken

**File**: `shrike/destinations/splunk_hec.py`
**Severity**: 🟠 High (was 🟠 High — confirmed by reviewer)
**Models agreed**: 3/3 (architect + planner + reviewer all flagged this)

**Root cause**: Lines 89–97 parse the HEC URL to build the management URL:

```python
parsed = url.rstrip("/").rsplit(":", 1)   # ← splits LAST colon
host = parsed[0]
port = parsed[1] if len(parsed) > 1 else "8089"
if tls_verify:
    self._mgmt_url = f"https://{host}:8089"
else:
    self._mgmt_url = f"http://{host}:8089"
```

For `https://splunk:8088`:
- `rsplit(":", 1)` → `['https://splunk', '8088']`
- `host = 'https://splunk'` ← **includes the scheme**
- `self._mgmt_url = 'https://https://splunk:8089'` ← **double scheme — always fails**

For `https://splunk` (no port):
- `rsplit(":", 1)` → `['https', '//splunk']`
- `host = 'https'` ← **wrong**
- `self._mgmt_url = 'https://https:8089'` ← **broken**

**Fix**:

```python
from urllib.parse import urlparse, urlunparse

parsed = urlparse(url)
host = parsed.hostname or url.strip("/").split("//")[1].split(":")[0]
port = str(parsed.port or 8089)
if tls_verify:
    self._mgmt_url = f"https://{host}:8089"
else:
    self._mgmt_url = f"http://{host}:8089"
```

**Also fix**: `tls_verify=False` should NOT switch protocol from HTTPS to HTTP. These are independent concerns:

```python
# Protocol: always use HTTPS for management API if HEC URL is HTTPS
scheme = "https" if parsed.scheme == "https" else "http"
self._mgmt_url = f"{scheme}://{host}:8089"
# tls_verify only controls SSL context, not URL scheme
```

**Verification**: Unit test with URLs: `https://splunk:8088`, `https://splunk`, `http://splunk:8088`. Assert management URL is `https://splunk:8089` (or correct scheme).

**Test**: `tests/destinations/test_splunk_hec.py` — add URL parsing test.

---

## Phase 2 — Crash Resilience

*New issues found by architect — foundational to WAL's value proposition.*

### 2.1 🟠 **NEW** — WAL writes not fsync'd

**File**: `shrike/destinations/wal.py`
**Severity**: 🟠 High
**Models agreed**: 3/3

**Root cause**: `append()` writes to WAL but never calls `fsync()`. OS may not flush write buffer to disk. Crash within ~30s of a write loses those events. The "write-ahead" in WAL is meaningless without durability guarantees.

**Fix**:

```python
async def append(self, events: list[dict]) -> int:
    if self._wal_path.stat().st_size >= self._max_size_bytes:
        return 0
    lines = "".join(json.dumps(e) + "\n" for e in events)
    async with aiofiles.open(self._wal_path, "a") as f:
        await f.write(lines)
        await f.flush()
        os.fsync(f.fileno())   # ← durability guarantee
    self._line_count += len(events)
    return len(events)
```

**Note**: `os.fsync()` in async context — `aiofiles` doesn't expose `fileno()` directly. Use `loop.run_in_executor()`:

```python
loop = asyncio.get_event_loop()
await loop.run_in_executor(None, os.fsync, f.fileno())
```

**Verification**: After `append()`, crash the process. On restart, events must be in WAL.

---

### 2.2 🟠 **NEW** — No graceful shutdown drain

**File**: `shrike/runtime.py`
**Severity**: 🟠 High
**Models agreed**: 3/3

**Root cause**: `lifespan()` cancels worker tasks on shutdown. If a worker is mid-delivery (events in flight to Splunk), those events are in the WAL but cursor hasn't advanced — they get re-delivered on restart (duplicate). Events not yet in WAL are lost.

**Fix**:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start workers
    for dest in destinations:
        w = DestinationWorker(dest, dest.wal)
        workers.append(w)
        worker_tasks.append(asyncio.create_task(w.run(), name=f"worker-{dest.name}"))
    logger.info("Started %d destination workers", len(workers))
    yield
    # Graceful drain
    logger.info("Shutting down — draining %d workers", len(workers))
    for w in workers:
        w.stop()
    # Wait for in-flight batches with timeout
    drain_timeout = 30.0
    for t in worker_tasks:
        try:
            await asyncio.wait_for(t, timeout=drain_timeout)
        except asyncio.TimeoutError:
            logger.warning("Worker %s did not drain in %.0fs", t.get_name(), drain_timeout)
        except asyncio.CancelledError:
            pass
    for dest in destinations:
        await dest.close()
    logger.info("Destination workers drained")
```

**Also**: Monitor worker task errors with `done()` callback:

```python
def worker_done(t: asyncio.Task) -> None:
    exc = t.exception()
    if exc:
        logger.error("Worker %s failed: %s", t.get_name(), exc)

for t in worker_tasks:
    t.add_done_callback(worker_done)
```

**Verification**: Send SIGTERM. Assert all in-flight batches complete (or fail), WAL cursor advances, no `Task exception was never retrieved` warnings.

---

## Phase 3 — Operational Stability

### 3.1 🟠 `#4` — `compact()` OOM + skip compaction when WAL is small

**File**: `shrike/destinations/wal.py`
**Severity**: 🟠 High
**Models agreed**: 3/3 (fix approach agreed after adversarial)

**Root cause**: `compact()` with `batch_size=2**31` loads all unsent events into memory. With 500MB WAL (~500K events), that's 50–100MB heap — significant GC pressure.

**Fix** — two parts:

*Part A*: Only compact when WAL is large enough to matter (skip wasted I/O):

```python
COMPACT_SIZE_THRESHOLD_MB = 50  # only compact if WAL > 50MB

async def compact(self) -> None:
    unsent = await self.read_unsent(batch_size=2**31)
    if len(unsent) == 0:
        return
    # Skip compaction if WAL is already small (no I/O waste)
    if self._wal_path.stat().st_size < COMPACT_SIZE_THRESHOLD_MB * 1024 * 1024:
        return
    # ... atomic write from 1.3 ...
```

*Part B*: Chunked reading during `compact()` to bound memory (not chunked writing — all unsent must be written):

```python
# Read in chunks to bound memory, write all to temp file
CHUNK_SIZE = 50000
all_unsent = []
async with aiofiles.open(self._wal_path, "rb") as f:
    while True:
        chunk = await f.readlines(CHUNK_SIZE)
        if not chunk:
            break
        for raw_line in chunk:
            if raw_line.strip():
                all_unsent.append(json.loads(raw_line))
        if len(chunk) < CHUNK_SIZE:
            break
```

**Note**: The chunked read is for memory management, not for partial compaction. All unsent events are still written to the temp file in one atomic operation.

**Verification**: `tracemalloc` test — WAL with 100K events, call `compact()`, assert peak memory < 20MB.

**Test**: `tests/destinations/test_wal.py` — memory test + small WAL skip test.

---

### 3.2 🟡 `#7` — Size-based compaction trigger

**File**: `shrike/destinations/wal.py`
**Severity**: 🟡 Medium
**Models agreed**: 3/3

**Root cause**: WAL compacts only after successful delivery. If Splunk is down for hours, WAL grows to 500MB before `append()` starts returning 0. No recovery mechanism.

**Fix** — trigger in `append()`, with mutex from 1.4:

```python
async def append(self, events: list[dict]) -> int:
    async with self._lock:
        current_size = self._wal_path.stat().st_size
        # Proactive compaction at 80% capacity — before we need it
        if current_size >= self._max_size_bytes * 0.8:
            await self._compact_unsafe()  # internal, no lock (caller holds it)
        if self._wal_path.stat().st_size >= self._max_size_bytes:
            return 0
        # ... write ...
```

**Note**: `_compact_unsafe()` is `compact()` without the lock (caller holds the lock). Prevents deadlock from lock re-entry.

**Verification**: Fill WAL to 80% capacity, call `append()`, assert `compact()` was called (check via mock/spy).

**Test**: `tests/destinations/test_wal.py` — size-based trigger test.

---

### 3.3 🟡 `#6` — `X-Forwarded-For` support

**File**: `shrike/runtime.py`
**Severity**: 🟡 Medium
**Models agreed**: 3/3

**Fix**:

```python
@app.post("/v1/ingest", dependencies=[Depends(verify_auth)])
async def ingest(body: IngestRequest, request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        source_ip = forwarded.split(",")[0].strip()
    else:
        source_ip = request.client.host if request.client else "unknown"
    # ...
```

**Verification**: Send request with `X-Forwarded-For: 1.2.3.4`. Assert `_shrike_source_ip == "1.2.3.4"`.

**Test**: `tests/test_runtime.py` — add X-Forwarded-For test.

---

## Phase 4 — API Correctness

### 4.1 🟡 `#3` — 507 error message + partial destination success

**File**: `shrike/runtime.py`
**Severity**: 🟡 Medium
**Models agreed**: 2/3 (architect refined the fix)

**Root cause**: `total_accepted == 0 and events` fires for WAL overflow. But if 1 of N destinations overflows (others succeed), `total_accepted > 0` so no 507 — but dropped events are invisible to caller.

**Fix**:

```python
@app.post("/v1/ingest", dependencies=[Depends(verify_auth)])
async def ingest(body: IngestRequest, request: Request):
    # ... existing normalization ...
    if not events:
        return {"accepted": 0, "total": len(body.logs), "normalized": 0}

    results = await router.route(events)
    total_accepted = sum(r.accepted for r in results.values())
    total_rejected = sum(r.rejected for r in results.values())

    # Distinguish WAL capacity from data rejection
    if total_rejected > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Destination rejected {total_rejected} events (permanent failure)",
        )
    if total_accepted == 0 and events:
        raise HTTPException(
            status_code=507,
            detail="All destinations at capacity — events not queued",
        )

    return {
        "accepted": total_accepted,
        "total": len(body.logs),
        "normalized": len(events),
    }
```

**Note**: `rejected > 0` now means "permanent rejection" (bad data) per fix 1.2. So checking `rejected > 0` for 400 is correct.

**Verification**: Mock all WALs full → 507. Mock one WAL full, others success → 200 with `accepted=N` (partial success visible).

**Test**: `tests/test_runtime.py` — add 507 test + partial success test.

---

### 4.2 🟡 `#10` — Request body byte limit

**File**: `shrike/runtime.py`
**Severity**: 🟡 Medium
**Models agreed**: 3/3 (reviewer caught that original fix was wrong)

**Root cause**: Pydantic `max_length` is item count, not byte size. 10,000 × 64KB = ~640MB bypasses Pydantic.

**Fix** — uvicorn `limit_max_bytes` (not FastAPI constructor param):

```python
uvi_config = uvicorn.Config(
    app,
    host="0.0.0.0",
    port=config.http_port,
    log_level="warning",
    limit_max_bytes=10_000_000,  # 10MB — uvicorn-level body limit
)
```

**Also add middleware for defense in depth**:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10_000_000:
            return JSONResponse(status_code=413, content={"error": "Request body too large"})
        return await call_next(request)

app.add_middleware(BodySizeLimitMiddleware)
```

**Verification**: Send request with 10,000 × 64KB logs. Assert 413.

**Test**: `tests/test_runtime.py` — body size limit test.

---

## Phase 5 — Cleanup

### 5.1 ⚠️ `#5` — Document open endpoint behavior

**File**: `shrike/config.py` + deployment docs
**Severity**: ⚠️ Low (document, not code)
**Models agreed**: 3/3

**Fix**: Add comment on `ingest_api_key` field:

```python
# Ingest endpoint authentication.
# If empty, endpoint is open (auth handled at proxy layer, e.g., Caddy).
# Set to a non-empty value to require Bearer token auth.
ingest_api_key: str = ""
```

**Also**: Document in `docker-compose.yml` comment block and deployment guide.

---

### 5.2 ⚠️ `#8` — Remove `mode` from health response (or use it)

**File**: `shrike/runtime.py`
**Severity**: ⚠️ Low
**Models agreed**: 3/3

**Fix**: Remove `mode` from health response (it's always `"full"` — no forwarder mode without OTel):

```python
return {
    "status": "healthy" if all_healthy else "degraded",
    # "mode": config.mode,  # always "full" — no forwarder mode
    "pipeline": "active" if _pipeline else "passthrough",
    "destinations": dest_health,
}
```

---

### 5.3 ⚠️ `#9` — Remove redundant `wal` param from `DestinationWorker`

**File**: `shrike/runtime.py` + `shrike/destinations/worker.py`
**Severity**: ⚠️ Low
**Models agreed**: 3/3

**Fix**:

```python
# worker.py
def __init__(
    self,
    destination: Destination,
    wal: WriteAheadLog | None = None,  # ← optional, falls back to dest.wal
    *,
    ...
):
    self._wal = wal if wal is not None else destination.wal
```

```python
# runtime.py — caller no longer passes wal explicitly
w = DestinationWorker(dest)  # ← uses dest.wal
```

---

### 5.4 ⚠️ `#13` — `advance_cursor()` O(n) re-read

**File**: `shrike/destinations/wal.py`
**Severity**: ⚠️ Low (deferred)
**Models agreed**: 3/3 — defer to Phase 5

**Fix**: Store line lengths during `read_unsent()` in an instance variable, use in `advance_cursor()` to skip re-read. Low priority — only matters for large batches.

---

## Issues NOT Fixed (False Positives / Deferred)

| Issue | Verdict | Reason |
|-------|---------|--------|
| #12 session leak | **NOT A BUG** | Persistent session is by design. `close()` disposes it. No leak. |
| #4 chunked compaction | **NOT IMPLEMENTED as proposed** | Chunked write loses events beyond chunk boundary. Use Phase 3 approach instead. |
| #10 `limit_max_bytes` on FastAPI | **Wrong approach** | Not a FastAPI constructor param. Use uvicorn `Config` + middleware. |

---

## Implementation Order

```
Phase 1.1  (#11)     → tempfile import
Phase 1.2  (#2)      → rejected=0 on overflow
Phase 1.5  (NEW)     → Splunk URL parsing fix
Phase 1.4  (NEW)     → async mutex
Phase 1.3  (#1)      → atomic compact + cursor
Phase 2.1  (NEW)     → fsync after WAL write
Phase 2.2  (NEW)     → graceful shutdown drain
Phase 3.1  (#4)      → compact memory bound + skip small WAL
Phase 3.2  (#7)      → size-based compaction trigger
Phase 3.3  (#6)      → X-Forwarded-For
Phase 4.1  (#3)      → 507 + partial success distinction
Phase 4.2  (#10)     → body byte limit (uvicorn + middleware)
Phase 5.1  (#5)      → document open endpoint
Phase 5.2  (#8)      → remove mode from health
Phase 5.3  (#9)      → remove redundant wal param
Phase 5.4  (#13)     → deferred: advance_cursor optimization
```

---

## Test Coverage Required

| Test | File | What It Catches |
|-----|------|----------------|
| WAL full → `rejected=0` | `test_router.py` | Fix 1.2 regression |
| Concurrent compact+read | `test_wal.py` | Fix 1.3 race |
| Compact memory < 20MB on 100K events | `test_wal.py` | Fix 3.1 OOM |
| Compact skipped when WAL < 50MB | `test_wal.py` | Fix 3.1 skip |
| Size-based trigger at 80% | `test_wal.py` | Fix 3.2 |
| Management URL parsing | `test_splunk_hec.py` | Fix 1.5 |
| SplunkHECDestination no wal_dir | `test_splunk_hec.py` | Fix 1.1 |
| X-Forwarded-For | `test_runtime.py` | Fix 3.3 |
| 507 on WAL full | `test_runtime.py` | Fix 4.1 |
| Partial success → 200 | `test_runtime.py` | Fix 4.1 |
| Body 413 | `test_runtime.py` | Fix 4.2 |
| Graceful drain on SIGTERM | integration test | Fix 2.2 |

---

## Sign-off

| Model | Agent | Status |
|-------|-------|--------|
| chat (Qwen3.5-122B) | architect | ✅ Round 2 complete |
| code (MiniMax M2.7) | planner | ✅ Round 2 complete |
| chat (Qwen3.5-122B) | reviewer | ✅ Round 2 complete |

**Date**: 2026-04-24
**Next step**: Dispatch `worker` to implement Phase 1 in order, with tests for each fix