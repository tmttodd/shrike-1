# Shrike — TODO

**Goal**: v0.1.0 release — production-ready, documented, tested, shippable.

**Last updated**: 2026-04-24
**Status**: 530 tests pass, 0 failures. Core runtime hardened. 55% code coverage.

---

## Priority Definitions

| Priority | Meaning |
|----------|---------|
| **P0** | Blocks v0.1.0 release |
| **P1** | Should land in v0.1.0 — significant quality gap |
| **P2** | Nice to have for v0.1.0 — polish |
| **P3** | v0.2.0 or later |

---

## P0 — Blocks Release

### Docs

- [x] **CHANGELOG.md** — No changelog exists. Create it. Every PR merged should be listed.
  - Add entries for PRs #4, #6, #8, #9 at minimum
  - Format: `## [0.1.0] — YYYY-MM-DD` with sections for Features, Fixes, Changes
  - Placeholder: `docs/CHANGELOG.md`

- [x] **API reference** — No reference for `/v1/ingest`, `/v1/normalize`, `/v1/batch`, `/health`
  - Request/response schemas for each endpoint
  - Error codes (400, 401, 413, 422, 507)
  - Example requests for each log format (syslog, CEF, JSON, LEEF)
  - Placeholder: `docs/api.md`

### Observability

- [x] **`/ready` probe** — Kubernetes readiness (can accept traffic?) separate from `/health` (is alive?)
  - Readiness: can accept requests (workers initialized, WALs ready)
  - Liveness: process is alive (current `/health` behavior)
  - Add `app.get("/ready")` in `runtime.py`
  - Test in `tests/test_runtime.py`

- [x] **Structured logging** — `logger.error/INFO/warning` with `%s` interpolation only
  - Replace with `structlog` for JSON logs in production
  - Fields: `event`, `dest`, `count`, `duration_ms`, `trace_id`
  - Consistent log levels: ERROR=failure, INFO=success, WARNING=degraded
  - Add to `runtime.py`, `wal.py`, `router.py`, `worker.py`, `splunk_hec.py`

### Version

- [x] **Single source of truth for version** — `0.1.0` hardcoded in 4 places
  - `shrike/__init__.py` → `__version__ = "0.1.0"` (keep this)
  - All others import from `shrike.__version__`
  - Files to update: `runtime.py`, `server.py`, `pyproject.toml`

### Security

- [x] **Rate limiting** — No per-client rate limiting on `/v1/ingest`
  - Add `slowapi` or middleware-based rate limit
  - Configurable via `SHRIKE_RATE_LIMIT_PER_CLIENT` (req/min)
  - Returns `429 Too Many Requests` when exceeded
  - Test in `tests/test_runtime.py`

---

## P1 — Significant Quality Gap

### Docs

- [x] **Deployment guide** — docs/deployment.md exists
  - Docker Compose (recommended)
  - Kubernetes (Helm chart or raw manifests)
  - systemd
  - Environment variables reference (all config keys)
  - TLS configuration
  - Reverse proxy (Caddy, nginx) configuration

- [x] **Contributing guide** — CONTRIBUTING.md exists
  - Dev setup (virtual env, pre-commit, test commands)
  - Pattern contribution workflow (133 YAML files)
  - OCSF class mapping process
  - PR requirements (tests pass, no coverage regression)

### Code Quality

- [x] **Dead code removal** — `server.py` and `pipeline_async.py` deleted
  - `server.py`: deleted (replaced by `runtime.py`)
  - `pipeline_async.py`: deleted (replaced by `pipeline.py`)
  - No imports reference them

- [ ] **`evaluate/dimensions.py` 0% coverage** — 233 lines, `TieredModeCacheQualityCheck` not implemented
  - Either implement the TODO at line 404, or remove the stub
  - If implemented, add tests in `tests/evaluate/`


- [ ] **`evaluate/golden_builder.py` 0% coverage** — 198 lines, completely untested
  - If used: add tests
  - If unused: delete or document purpose

### Testing Gaps (High Impact)

- [x] **`/v1/normalize` endpoint** — Tests exist in test_runtime.py
  - `NormalizeRequest` → normalization pipeline → OCSF events
  - Happy path, empty logs, invalid log format tested

- [x] **`/v1/batch` endpoint** — Tests exist in test_runtime.py
  - `BatchRequest` → batch processing
  - Happy path, empty batch, oversized batch tested

- [ ] **WAL `compact()` memory bounds** — No test for Phase 3.1 memory guarantee
  - Plan says: `tracemalloc` test — 100K events, peak < 20MB
  - `tests/destinations/test_wal.py` has `test_compact_chunked_reading_bounds_memory` — verify it works
  - Run it specifically: `.venv/bin/pytest test_wal.py::test_compact_chunked_reading_bounds_memory -v`

- [ ] **Graceful shutdown drain** — `test_shutdown_awaits_tasks_with_timeout` exists but doesn't test actual drain
  - Current test only checks task naming
  - Add test: SIGTERM → 30s drain → verify events delivered, not dropped
  - Mock worker task that takes 5s, send SIGTERM, verify it completes

- [ ] **`router.route()` partial success** — `test_router_independent_failure` exists but partial success not tested
  - Test: one WAL full (0 accepted), one success (1 accepted) → 200 with `accepted=1`
  - `test_ingest_returns_200_with_partial_success` covers the API but not the router directly

### Observability

- [x] **`/metrics` endpoint** — Implemented in `runtime.py`
  - All 7 metrics wired up (counters, gauges, histogram)
  - Updated in ingest endpoint and destination workers
  - Test in `tests/test_runtime.py::test_metrics_endpoint`

### Patterns

- [x] **Auto-generated patterns** — documented in `patterns/auto/README.md`
  - 7 files from Splunkbase TAs
  - Status: Active (maintained by Shrike team)
  - Regeneration script: `scripts/regenerate_auto_patterns.py`

---

## P2 — Polish

### Docs

- [x] **Architecture doc** — `docs/architecture.md` exists
  - System diagram (ingestion → detection → classification → extraction → routing → destinations)
  - OCSF schema version and schema file locations
  - Extraction tier cascade (Tier 0 fingerprint → Tier 3 LLM)
  - WAL design decisions (cursor, compaction, atomic rename)
  - Destination fan-out (independent WAL per destination)

- [x] **Pattern contribution guide** — `docs/patterns.md` exists
  - YAML format reference (match, ocsf_class_uid, field_map)
  - How to test new patterns locally
  - How to validate OCSF class mappings

### Code Quality

- [ ] **`evaluate/hallucination.py` 25% coverage** — 60 lines, 45 uncovered
  - `HallucinationDetector` — detects LLM hallucination in extractions
  - Add tests in `tests/evaluate/`

- [ ] **`evaluate/attack_coverage.py` 10% coverage** — 109 lines, 98 uncovered
  - `AttackCoverageEvaluator` — MITRE ATT&CK coverage
  - Add tests in `tests/evaluate/`

- [ ] **`extractor/ner_extractor.py` 30% coverage** — 105 lines, 74 uncovered
  - `NERExtractor` — SecureBERT named entity extraction
  - Add tests in `tests/extractor/`

- [ ] **`extractor/schema_injected_extractor.py` 38% coverage** — 128 lines, 80 uncovered
  - `SchemaInjectedExtractor` — schema-guided extraction
  - Add tests in `tests/extractor/`

- [ ] **`extractor/tiered_extractor.py` 53% coverage** — 196 lines, 92 uncovered
  - `TieredExtractor` — 6-tier cascade
  - Add tests in `tests/extractor/`

- [ ] **`extractor/embedding_field_mapper.py` 48% coverage** — 141 lines, 74 uncovered
  - `EmbeddingFieldMapper` — embedding-based field mapping
  - Add tests in `tests/extractor/`

- [ ] **`detector/format_detector.py` 79% coverage** — 134 lines, 28 uncovered
  - `FormatDetector` — 14 format detection
  - Add tests for uncovered branches in `tests/detector/`

- [ ] **`detector/sigma/rule_engine.py` 37% coverage** — 108 lines, 68 uncovered
  - `SigmaRuleEngine` — Sigma rule evaluation
  - Add tests in `tests/detector/sigma/`

- [ ] **`detector/sigma/ocsf_mapper.py` 71% coverage** — 28 lines, 8 uncovered
  - `OCSFMapper` — Sigma to OCSF mapping
  - Add tests in `tests/detector/sigma/`

- [ ] **`detector/sigma/rule_loader.py` 66% coverage** — 62 lines, 21 uncovered
  - `SigmaRuleLoader` — loads Sigma rules from filesystem
  - Add tests in `tests/detector/sigma/`

- [ ] **`detector/correlation_engine.py` 30% coverage** — 47 lines, 33 uncovered
  - `CorrelationEngine` — event correlation
  - Add tests in `tests/detector/`

- [ ] **`extractor/fingerprint_cache.py` 56% coverage** — 170 lines, 75 uncovered
  - `FingerprintCache` — exact-match extraction cache
  - Add tests in `tests/extractor/`

- [ ] **`extractor/field_mapper.py` 63% coverage** — 130 lines, 48 uncovered
  - `FieldMapper` — field name normalization
  - Add tests in `tests/extractor/`

- [ ] **`extractor/preparsers.py` 89% coverage** — 139 lines, 15 uncovered
  - `Preparsers` — pre-parsing for known formats
  - Add tests for uncovered preparsers in `tests/extractor/`

- [ ] **`extractor/template_miner.py` 79% coverage** — 261 lines, 55 uncovered
  - `TemplateMiner` — Drain3 template learning
  - Add tests in `tests/extractor/`

- [ ] **`evaluate/coercion.py` 53% coverage** — 223 lines, 105 uncovered
  - `CoercionEvaluator` — type coercion quality
  - Add tests in `tests/evaluate/`

- [ ] **`evaluate/observables.py` 73% coverage** — 45 lines, 12 uncovered
  - `ObservablesEvaluator` — observable extraction quality
  - Add tests in `tests/evaluate/`

- [ ] **`filter/filter_engine.py` 90% coverage** — 86 lines, 9 uncovered
  - `FilterEngine` — filter pack execution
  - Add tests for uncovered filter operations in `tests/filter/`

- [ ] **`triage/router.py` 98% coverage** — 41 lines, 1 uncovered
  - `TriageRouter` — routing to triage pipeline
  - Add test for uncovered branch in `tests/triage/`

- [ ] **`triage/relevance.py` 98% coverage** — 97 lines, 2 uncovered
  - `RelevanceScorer` — relevance scoring
  - Add tests in `tests/triage/`

- [ ] **`detector/alert.py` 95% coverage** — 21 lines, 1 uncovered
  - `AlertGenerator` — alert generation
  - Add test in `tests/detector/`

- [ ] **`validator/ocsf_validator.py` 79% coverage** — 135 lines, 29 uncovered
  - `OCSFValidator` — schema validation
  - Add tests for uncovered validation paths in `tests/validator/`

### CLI

- [ ] **`shrike` CLI completeness** — `--detect-only`, `--classify-only` flags exist but not tested
  - Add CLI tests in `tests/test_cli.py`
  - Document CLI in README or create `docs/cli.md`

### Patterns

- [ ] **More vendor patterns** — 133 pattern files, 50+ vendors covered
  - Survey which major vendors are missing (cloud providers, SaaS, network gear)
  - Add top 10 missing vendors
  - Track coverage metric: `scripts/evaluate.py` → classification accuracy by vendor

### Performance

- [ ] **`scripts/load_test.py`** — Load test script exists, not integrated into CI
  - Run it against a real deployment
  - Add to CI as a separate workflow (not blocking, informational)
  - Document expected throughput (events/sec) for sizing guide

### Security

- [ ] **TLS configuration completeness** — `splunk_tls_verify` exists but not tested end-to-end
  - Add test: verify TLS cert validation when `tls_verify=True`
  - Add test: verify connection fails gracefully when cert is invalid

---

## P3 — v0.2.0

### Features

- [ ] **LLM extraction tier** — Tiers 2 & 3 (LLM-assisted) not tested in CI
  - `SHRIKE_LLM_URL`, `SHRIKE_LLM_MODEL`, `SHRIKE_LLM_API_KEY` configured but untested
  - Add integration tests with mock LLM endpoint
  - Document the 6-tier cascade in docs/


- [ ] **OTel Collector re-integration** — OTel Collector was removed, may be needed for traces
  - Re-add as optional (not embedded): `SHRIKE_OTEL_ENABLED=false`
  - Only if `otel` Python package is installed
  - Traces: Jaeger, Zipkin, OTLP exporters

- [ ] **Multi-destination routing** — `router.route()` fans out but not tested with 3+ destinations
  - Test: 3 destinations, one fails, verify others still deliver
  - Test: WAL overflow on one destination, others continue

- [ ] **Filter pack editor** — No UI or CLI to manage filter packs
  - `shrike filter list` — list available packs
  - `shrike filter validate <pack>` — validate YAML syntax
  - `shrike filter test <pack> <log>` — test a log against a pack

- [ ] **Pattern editor** — No CLI to manage patterns
  - `shrike pattern validate <file>` — validate YAML syntax
  - `shrike pattern test <file> <log>` — test a log against a pattern file
  - `shrike pattern coverage <logs>` — show which patterns match a log set

- [ ] **Dashboard** — No admin UI
  - Health status per destination
  - WAL pending/disk per destination
  - Events/min throughput
  - Error rates
  - Could be a simple FastAPI admin panel or Grafana dashboard

### Observability

- [ ] **Alerting** — No alerting when destinations fail
  - Alert on: destination unhealthy for > 5 min
  - Alert on: WAL at 90% capacity
  - Alert on: rejection rate > 1%
  - Integrations: PagerDuty, Slack, email

- [ ] **Distributed tracing** — No trace IDs in logs
  - Add `X-Trace-ID` header support
  - Propagate trace ID through extraction tiers
  - Correlate across destinations

### Patterns

- [ ] **CEF/LEEF full support** — Partial support only
  - Full CEF field extraction (all 90+ CEF field names)
  - Full LEEF field extraction (all LEEF field names)
  - Add tests for edge-case CEF/LEEF logs

- [ ] **Auto-pattern learning** — Integrate into CLI (`shrike learn <log-file>`)
  - Currently: patterns/auto/ is maintained by Shrike team
  - Future: user-facing pattern learning

### Performance

- [ ] **Benchmark suite** — No systematic benchmarks
  - Events/sec by log format (syslog vs JSON vs CEF)
  - Memory usage at 100K pending events
  - WAL compaction time at 500MB
  - LLM extraction latency (Tier 2 vs Tier 3)
  - Publish to README as "Performance" section

### Docs

- [ ] **Blog posts** — Pipeline: draft → Todd edits → Ghost publish
  - "How Shrike normalizes any log format to OCSF"
  - "The 6-tier extraction engine"
  - "Building a security data pipeline with Shrike and Splunk"

---

## Completed This Session

- [x] PR #6 — 13-issue production runtime hardening (Ralph Wiggum reviewed)
- [x] PR #8 — 507 WAL full + partial success tests
- [x] PR #9 — WAL optimization, body limit middleware, auth fix, config fail-fast, default index, Splunk HEC mock fixes
- [x] PR #10 — TODO.md, CHANGELOG.md, API reference, /ready probe, structured logging, version single source, rate limiting
- [x] PR #13 — P1 items: deployment guide, contributing guide, /metrics, tests, dead code deleted
- [x] PR #14 — Fix Quality Gate pip CVE false positive, test runner target
- [x] Architecture doc — docs/architecture.md (system diagram, OCSF schema, WAL design, tier cascade)
- [x] Pattern guide — docs/patterns.md (YAML format, testing, OCSF class reference)
- [x] Auto-patterns doc — patterns/auto/README.md (7 files, Splunkbase TAs)
- [x] 530+ tests pass, 0 failures

---

## Release Criteria — v0.1.0

Before tagging and publishing, everything above P0 must be resolved:

| Item | Status |
|------|--------|
| CHANGELOG.md | ✅ Done |
| API reference | ✅ Done |
| `/ready` probe | ✅ Done |
| Structured logging | ✅ Done |
| Version single source | ✅ Done |
| Rate limiting | ✅ Done |
| Deployment guide | ✅ Done |
| Contributing guide | ✅ Done |
| Dead code (server.py, pipeline_async.py) | ✅ Deleted |
| `/v1/normalize` tests | ✅ Done |
| `/v1/batch` tests | ✅ Done |
| `/metrics` endpoint | ✅ Done |
| Auto-patterns status | ✅ Documented in patterns/auto/README.md |