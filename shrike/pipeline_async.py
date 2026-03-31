"""Async ring buffer pipeline for Shrike's tiered extraction engine.

Separates fast-path (Tier 1 pattern extraction, <1ms) from slow-path
(Tier 2/3 LLM enrichment, 200-750ms) using a bounded asyncio.Queue
and a configurable worker pool.

Architecture:
  1. process() runs Tier 1 synchronously, returns immediately
  2. Shallow results (< 3 real fields) are queued for LLM enrichment
  3. Workers drain the queue, calling Tier 2 or Tier 3 extractors
  4. Enriched results are passed to a callback
  5. Backpressure: when queue is full, shallow results are dropped
     (Tier 1 result is preserved — we never lose data)

Usage:
    pipe = AsyncShrikePipeline(
        extractor_api="http://192.168.20.16:8000/v1",
        extractor_model="subagent",
        num_workers=4,
        on_enriched=lambda r: print(f"Enriched: {len(r.event)} fields"),
    )
    await pipe.start_workers()
    result = await pipe.process(raw_log, class_uid=3002, class_name="Authentication")
    # result is available immediately (Tier 1)
    # ... later, on_enriched fires with LLM-enhanced version
    await pipe.stop_workers()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import aiohttp

from shrike.detector.format_detector import detect_format, LogFormat
from shrike.extractor.pattern_extractor import PatternExtractor
from shrike.extractor.preparsers import preparse
from shrike.extractor.schema_injected_extractor import (
    ExtractionResult,
    SchemaInjectedExtractor,
    SYSTEM_PROMPT,
    _build_schema_context,
    _extract_json,
)
from shrike.extractor.tiered_extractor import PreparseExtractor
from shrike.pipeline import PipelineResult
from shrike.validator.ocsf_validator import OCSFValidator

logger = logging.getLogger("shrike.pipeline_async")

# Fields that are always present in even the emptiest extraction and
# should not count toward "real" field richness.
_META_FIELDS = frozenset({
    "class_uid", "class_name", "category_uid", "category_name",
    "raw_data", "raw_log",
})

# Minimum number of non-meta fields to consider a Tier 1 result "rich enough"
# to skip LLM enrichment.
SHALLOW_THRESHOLD = 3


@dataclass
class PipelineStats:
    """Accumulator for pipeline throughput metrics."""
    processed: int = 0
    fast_path: int = 0       # Rich Tier 1 results (no enrichment needed)
    queued: int = 0          # Sent to enrichment queue
    enriched: int = 0        # Successfully enriched by LLM
    enrichment_errors: int = 0
    dropped: int = 0         # Dropped due to full queue (backpressure)
    total_process_ms: float = 0.0
    total_enrich_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        avg_process = (self.total_process_ms / self.processed) if self.processed else 0.0
        avg_enrich = (self.total_enrich_ms / self.enriched) if self.enriched else 0.0
        return {
            "processed": self.processed,
            "fast_path": self.fast_path,
            "queued": self.queued,
            "enriched": self.enriched,
            "enrichment_errors": self.enrichment_errors,
            "dropped": self.dropped,
            "avg_process_ms": round(avg_process, 2),
            "avg_enrich_ms": round(avg_enrich, 2),
            "rich_rate": round(
                (self.fast_path + self.enriched) / max(self.processed, 1), 3
            ),
        }


def _count_real_fields(event: dict[str, Any]) -> int:
    """Count non-meta fields in the extracted event."""
    count = 0
    for key in event:
        if key not in _META_FIELDS:
            count += 1
    return count


class AsyncShrikePipeline:
    """Async pipeline with ring buffer for LLM enrichment."""

    def __init__(
        self,
        patterns_dir: Path | None = None,
        schemas_dir: Path | None = None,
        extractor_api: str = "http://localhost:11434/v1",
        extractor_model: str = "shrike-extractor",
        api_key: str = "not-needed",
        queue_size: int = 1000,
        num_workers: int = 4,
        on_enriched: Callable[[PipelineResult], None] | None = None,
        shallow_threshold: int = SHALLOW_THRESHOLD,
    ):
        """Initialize the async pipeline.

        Args:
            patterns_dir: Path to YAML pattern files for Tier 1.
            schemas_dir: Path to OCSF schema JSON files.
            extractor_api: OpenAI-compatible API base URL for LLM extraction.
            extractor_model: Model name for the LLM API.
            api_key: API key for the LLM endpoint.
            queue_size: Max entries in the enrichment ring buffer.
            num_workers: Number of async workers draining the queue.
            on_enriched: Callback invoked with the enriched PipelineResult.
            shallow_threshold: Min real fields to consider Tier 1 "rich enough".
        """
        base_dir = Path(__file__).parent.parent
        if schemas_dir is None:
            schemas_dir = base_dir / "schemas" / "ocsf_v1.3" / "classes"
        else:
            schemas_dir = Path(schemas_dir)
        if patterns_dir is None:
            patterns_dir = base_dir / "patterns"
        else:
            patterns_dir = Path(patterns_dir)

        self._api_base = extractor_api.rstrip("/")
        self._model = extractor_model
        self._api_key = api_key
        self._num_workers = num_workers
        self._on_enriched = on_enriched
        self._shallow_threshold = shallow_threshold

        # Tier 1: Pattern extractor (sync, fast)
        self._pattern_extractor = PatternExtractor(patterns_dir)

        # Schema cache for Tier 2/3 enrichment
        self._schemas: dict[int, dict] = {}
        self._schemas_dir = schemas_dir
        self._load_schemas(schemas_dir)

        # Validator for post-enrichment validation
        self._validator = OCSFValidator(schemas_dir)

        # Ring buffer: bounded asyncio.Queue
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._queue_size = queue_size

        # Worker tasks
        self._workers: list[asyncio.Task] = []
        self._running = False

        # Shared aiohttp session (created in start_workers)
        self._session: aiohttp.ClientSession | None = None

        # Stats
        self._stats = PipelineStats()

    def _load_schemas(self, schemas_dir: Path) -> None:
        """Load OCSF class schemas from disk."""
        if not schemas_dir.exists():
            return
        for f in schemas_dir.glob("class_*.json"):
            try:
                with open(f) as fh:
                    schema = json.load(fh)
                self._schemas[schema["class_uid"]] = schema
            except Exception:
                pass

    async def process(
        self,
        raw_log: str,
        class_uid: int = 0,
        class_name: str = "",
    ) -> PipelineResult:
        """Process a log line. Returns Tier 1 result immediately.

        If the Tier 1 result is shallow (< threshold real fields),
        the log is queued for async LLM enrichment. The on_enriched
        callback fires later with the improved result.

        Args:
            raw_log: Raw log line to process.
            class_uid: OCSF class UID (pre-classified).
            class_name: OCSF class name.

        Returns:
            PipelineResult from Tier 1 (available immediately).
        """
        t0 = time.monotonic()

        # Detect format
        log_format = detect_format(raw_log)

        # Tier 1: Pattern extraction (sync, <10ms)
        extraction = self._pattern_extractor.try_extract(
            raw_log, log_format, class_uid, class_name,
        )

        tier = 1 if extraction is not None else 0
        if extraction is None:
            extraction = ExtractionResult(
                event={"class_uid": class_uid, "raw_data": raw_log},
                class_uid=class_uid,
                class_name=class_name,
                raw_log=raw_log,
            )

        elapsed = (time.monotonic() - t0) * 1000

        # Build PipelineResult
        result = PipelineResult(
            raw_log=raw_log,
            log_format=log_format,
            class_uid=class_uid,
            class_name=class_name,
            event=extraction.event,
            extraction_tier=tier,
            extract_ms=elapsed,
            total_ms=elapsed,
        )

        self._stats.processed += 1
        self._stats.total_process_ms += elapsed

        # Decide: rich enough or needs enrichment?
        real_fields = _count_real_fields(extraction.event)
        if real_fields >= self._shallow_threshold:
            self._stats.fast_path += 1
            return result

        # Shallow result — queue for enrichment
        item = (result, raw_log, class_uid, class_name, log_format)
        try:
            self._queue.put_nowait(item)
            self._stats.queued += 1
        except asyncio.QueueFull:
            # Backpressure: drop newest shallow result, keep Tier 1 result
            self._stats.dropped += 1
            logger.debug("Enrichment queue full — dropped log for enrichment")

        return result

    async def process_batch(
        self,
        logs: list[tuple[str, int, str]],
    ) -> list[PipelineResult]:
        """Process a batch of (raw_log, class_uid, class_name) tuples.

        Returns Tier 1 results immediately. Shallow results are queued.
        """
        results = []
        for raw_log, class_uid, class_name in logs:
            r = await self.process(raw_log, class_uid, class_name)
            results.append(r)
        return results

    async def start_workers(self) -> None:
        """Start the enrichment worker pool and shared HTTP session."""
        if self._running:
            return

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120),
        )
        self._running = True

        for i in range(self._num_workers):
            task = asyncio.create_task(
                self._enrichment_worker(i),
                name=f"shrike-enrichment-{i}",
            )
            self._workers.append(task)

        logger.info(
            "Started %d enrichment workers (queue_size=%d)",
            self._num_workers, self._queue_size,
        )

    async def stop_workers(self) -> None:
        """Drain the queue and stop workers gracefully."""
        if not self._running:
            return

        self._running = False

        # Send poison pills to each worker
        for _ in self._workers:
            await self._queue.put(None)

        # Wait for workers to finish
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

        self._workers.clear()

        # Close HTTP session
        if self._session:
            await self._session.close()
            self._session = None

        logger.info("Enrichment workers stopped")

    async def _enrichment_worker(self, worker_id: int) -> None:
        """Worker that pulls from the queue and calls LLM for enrichment.

        Each item is a tuple:
          (PipelineResult, raw_log, class_uid, class_name, log_format)

        The worker tries Tier 2 (pre-parse + LLM mapping) first. If that
        fails, falls back to Tier 3 (full schema-injected LLM). Enriched
        fields are merged into the existing Tier 1 event.
        """
        logger.debug("Enrichment worker %d started", worker_id)

        while True:
            item = await self._queue.get()
            if item is None:
                # Poison pill — shutdown
                self._queue.task_done()
                break

            result, raw_log, class_uid, class_name, log_format = item
            t0 = time.monotonic()

            try:
                enriched_event, enriched_confidence = await self._enrich(
                    raw_log, class_uid, class_name, log_format,
                )

                if enriched_event is not None:
                    # Merge: LLM fields fill gaps in Tier 1 event
                    merged = dict(result.event)  # Start with Tier 1
                    for key, value in enriched_event.items():
                        if key not in merged or key in _META_FIELDS:
                            merged[key] = value
                    result.event = merged
                    result.extraction_tier = 2  # Mark as enriched

                    # Update confidence dict if present on the extraction
                    if hasattr(result, "_confidence"):
                        result._confidence.update(enriched_confidence)

                    # Validate the enriched event
                    validation = self._validator.validate(
                        result.event, class_uid=class_uid,
                    )
                    result.valid = validation.valid
                    result.validation_errors = validation.error_count
                    result.validation_warnings = validation.warning_count
                    result.field_coverage = validation.field_coverage

                    elapsed = (time.monotonic() - t0) * 1000
                    result.extract_ms += elapsed
                    result.total_ms += elapsed
                    self._stats.enriched += 1
                    self._stats.total_enrich_ms += elapsed

                    # Fire callback
                    if self._on_enriched is not None:
                        try:
                            self._on_enriched(result)
                        except Exception:
                            logger.exception("on_enriched callback error")
                else:
                    self._stats.enrichment_errors += 1

            except Exception:
                logger.exception(
                    "Worker %d enrichment error for log: %.60s...",
                    worker_id, raw_log,
                )
                self._stats.enrichment_errors += 1

            self._queue.task_done()

        logger.debug("Enrichment worker %d stopped", worker_id)

    async def _enrich(
        self,
        raw_log: str,
        class_uid: int,
        class_name: str,
        log_format: LogFormat,
    ) -> tuple[dict[str, Any] | None, dict[str, str]]:
        """Try Tier 2, then Tier 3 enrichment via async LLM call.

        Returns (enriched_event, confidence_dict) or (None, {}).
        """
        schema = self._schemas.get(class_uid)
        if schema is None:
            return None, {}

        # Try Tier 2: Pre-parse + LLM mapping
        preparsed = preparse(raw_log, log_format)
        if preparsed is not None and len(preparsed.fields) >= 2:
            event = await self._tier2_async(preparsed, schema, class_uid)
            if event is not None:
                confidence = {k: "llm" for k in event if k not in _META_FIELDS}
                return event, confidence

        # Fall back to Tier 3: Full schema-injected LLM
        event = await self._tier3_async(raw_log, schema, class_uid, class_name)
        if event is not None:
            confidence = {k: "llm" for k in event if k not in _META_FIELDS}
            return event, confidence

        return None, {}

    async def _tier2_async(
        self,
        preparsed,
        schema: dict,
        class_uid: int,
    ) -> dict[str, Any] | None:
        """Async Tier 2: pre-parse fields + LLM mapping."""
        source_fields = [f for f in preparsed.fields if not f.startswith("_")]
        if not source_fields:
            source_fields = list(preparsed.fields.keys())

        attrs = schema.get("attributes", {})
        ocsf_fields = []
        for name, spec in attrs.items():
            req = "REQUIRED" if spec.get("requirement") == "required" else spec.get("requirement", "optional")
            ocsf_fields.append(f"{name} ({req})")

        prompt = (
            f"Map source fields to OCSF {schema['class_name']} (class_uid: {class_uid}).\n"
            f"Source fields: {', '.join(source_fields)}\n"
            f"OCSF schema fields: {', '.join(ocsf_fields[:15])}\n"
            f"Output a JSON object with OCSF field names as keys and source field names as values.\n"
            f"Also set: class_uid={class_uid}, class_name=\"{schema['class_name']}\", "
            f"category_uid={class_uid // 1000}, severity_id (1-6), activity_id (0-99).\n"
            f"JSON:"
        )

        response = await self._call_llm(
            system=PreparseExtractor.MAPPING_SYSTEM,
            user=prompt,
            max_tokens=256,
        )
        if response is None:
            return None

        mapping = _extract_json(response)
        if mapping is None or not isinstance(mapping, dict):
            return None

        # Apply mapping: look up values from preparsed fields
        event: dict[str, Any] = {}
        for ocsf_field, value in mapping.items():
            if isinstance(value, str) and value in preparsed.fields:
                event[ocsf_field] = preparsed.fields[value]
            else:
                event[ocsf_field] = value

        event.setdefault("class_uid", class_uid)
        event.setdefault("class_name", schema.get("class_name", ""))
        event.setdefault("category_uid", class_uid // 1000)
        if "time" not in event and preparsed.timestamp:
            event["time"] = preparsed.timestamp

        return event

    async def _tier3_async(
        self,
        raw_log: str,
        schema: dict,
        class_uid: int,
        class_name: str,
    ) -> dict[str, Any] | None:
        """Async Tier 3: full schema-injected LLM extraction."""
        schema_context = _build_schema_context(schema)
        user_prompt = (
            f"Schema:\n{schema_context}\n\nRaw log:\n{raw_log}\n\nExtract OCSF JSON:"
        )

        response = await self._call_llm(
            system=SYSTEM_PROMPT,
            user=user_prompt,
            max_tokens=2048,
        )
        if response is None:
            return None

        event = _extract_json(response)
        if event is None:
            return None

        event["class_uid"] = class_uid
        event.setdefault("class_name", schema.get("class_name", class_name))
        event.setdefault("category_uid", class_uid // 1000)
        return event

    async def _call_llm(
        self,
        system: str,
        user: str,
        max_tokens: int = 2048,
    ) -> str | None:
        """Make an async HTTP call to the OpenAI-compatible LLM API.

        Sends chat_template_kwargs to disable thinking for vLLM.
        """
        if self._session is None:
            logger.error("No HTTP session — call start_workers() first")
            return None

        url = f"{self._api_base}/chat/completions"
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

        try:
            async with self._session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(
                        "LLM API returned %d: %.200s", resp.status, body,
                    )
                    return None
                data = await resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception:
            logger.exception("LLM API call failed")
            return None

    @property
    def queue_depth(self) -> int:
        """Current number of logs waiting for enrichment."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict[str, Any]:
        """Pipeline statistics: processed, enriched, dropped, avg latency."""
        return self._stats.to_dict()

    @property
    def is_running(self) -> bool:
        """Whether enrichment workers are running."""
        return self._running
