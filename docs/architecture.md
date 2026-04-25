# Shrike Architecture

Shrike is a security data normalization platform that ingests raw logs in any format and outputs structured OCSF v1.3 events.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Ingestion Interfaces                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ HTTP API │  │  Syslog  │  │   OTLP   │  │  File/JSONL dir   │  │
│  │ :8080   │  │  :1514  │  │ :4317/8  │  │  watch directory  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
└───────┼─────────────┼─────────────┼─────────────────┼────────────┘
        │             │             │                  │
        ▼             ▼             ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Normalization Pipeline                          │
│                                                             │
│  ┌─────────┐   ┌───────────┐   ┌───────────┐   ┌──────────┐  │
│  │ Detect  │──▶│ Classify  │──▶│ Extract  │──▶│ Validate │  │
│  │  Format│   │ OCSF Class│   │  Fields  │   │  OCSF   │  │
│  └─────────┘   └───────────┘   └───────────┘   └──────────┘  │
│       │                                                 │      │
│       │              ┌─────────────────────┐             │      │
│       └─────────────▶│  Write-Ahead Log    │◀────────────┘      │
│                     │  (per destination) │                    │
│                     └─────────────────────┘                   │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Destinations                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐     │
│  │ Splunk  │  │File JSONL│  │  Future: S3, Kafka,     │     │
│  │   HEC   │  │  output │  │  GCP Pub/Sub, Azure     │     │
│  └──────────┘  └──────────┘  └──────────────────────────┘     │
└───────────────────────────────────────────────────────────────┘
```

## Extraction Tier Cascade

Shrike uses a 6-tier extraction cascade, falling through from fastest to most thorough:

| Tier | Method | Speed | When Used |
|------|--------|-------|--------|----------|
| **0** | Fingerprint cache | `O(1)` | Exact log seen before |
| **1** | Pattern library | `<1ms` | 2,052 YAML patterns + 698 field aliases |
| **1.5a** | NER extraction | `~50ms` | SecureBERT named entity recognition |
| **1.5b** | Template miner | `~1ms` | Drain3 template learning |
| **2** | Pre-parse + LLM | `~200ms` | Structured field mapping |
| **3** | Full LLM | `~750ms` | Complete extraction |

**Self-improving**: Every log processed teaches the cache and template miner, making future extractions faster.

## OCSF Schema

- **Version**: OCSF v1.3
- **Schema files**: `schemas/ocsf_v1.3/`
- **Class mappings**: `schemas/class_mapping.yaml`

### Supported OCSF Classes (45 total)

**IAM**:
- `3001` — Entity Account Created
- `3002` — Authentication
- `3003` — Authorization
- `3004` — Account Change
- `3005` — Account Disable
- `3006` — Account Enable
- `3007` — Account Removed

**Network Activity**:
- `4001` — Network Activity
- `4002` — Network Connection
- `4003` — DNS Query
- `4004` — File Transfer

**System Activity**:
- `5001` — Process Started
- `5002` — Device Config Change
- `5003` — Audit Log

**Security Findings**:
- `6001` — Threat Detection
- `6002` — Malware Detection
- `6003` — Vulnerability

## WAL Design

The Write-Ahead Log provides durability and delivery guarantees:

### Cursor Management
- Cursor file: `<dest>.cursor`
- Stores: `offset` (bytes), `line_count` (events), `last_timestamp`
- Atomic update: write to temp file, then `os.replace()`

### Compaction
- Trigger: WAL at 80% capacity (`SHRIKE_WAL_MAX_MB * 0.8`)
- Method: chunked reading (`COMPACT_CHUNK_SIZE = 50,000` events)
- Memory bound: `<20MB` peak for 100K events

### Concurrency
- `asyncio.Lock()` on all WAL operations
- Safe for multi-worker access

## Destination Fan-Out

Each destination has an independent WAL:

```
router.route(events)
    │
    ├──▶ splunk_hec ──▶ WAL: splunk_hec.wal
    │
    ├──▶ file_jsonl ──▶ WAL: file_jsonl.wal
    │
    └──▶ (future) ──▶ WAL: <name>.wal
```

Events are delivered if **any** destination accepts them. Partial success is supported.

## Observability

### Metrics (`/metrics`)

Prometheus-format metrics:

| Metric | Type | Labels | Description |
|-------|------|-------|-------------|
| `shrike_events_accepted_total` | Counter | `dest` | Events accepted |
| `shrike_events_rejected_total` | Counter | `dest` | Events rejected |
| `shrike_events_normalized_total` | Counter | — | Events normalized |
| `shrike_wal_pending` | Gauge | `dest` | Pending events in WAL |
| `shrike_wal_disk_mb` | Gauge | `dest` | WAL disk usage |
| `shrike_dest_health` | Gauge | `dest` | 1=healthy, 0=unhealthy |
| `shrike_request_duration_ms` | Histogram | `endpoint` | Request latency |

### Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Liveness probe (is alive?) |
| `/ready` | Readiness probe (can accept traffic?) |

## Security

### Authentication
- `INGEST_API_KEY`: Bearer token for `/v1/ingest`
- HMAC comparison to prevent timing attacks

### Rate Limiting
- `SHRIKE_RATE_LIMIT_PER_CLIENT`: requests per minute (default: 100/minute)
- Returns `429 Too Many Requests` when exceeded

### TLS
- `SHRIKE_SPLUNK_TLS_VERIFY`: verify Splunk HEC certificate

## Configuration

All configuration via environment variables. See `docs/deployment.md` for full reference.

## Directory Structure

```
shrike/
├── shrike/                    # Main package
│   ├── runtime.py          # FastAPI server
│   ├── pipeline.py       # Normalization pipeline
│   ├── config.py        # Configuration
│   ├── metrics.py      # Prometheus metrics
│   ├── collector/       # OTel Collector (optional)
│   ├── classifier/      # ML log classifier
│   ├── detector/       # Format detection
│   ├── extractor/      # 6-tier extraction
│   ├── destinations/   # WAL, Splunk HEC, File JSONL
│   ├── evaluate/       # Quality evaluation
│   ├── filter/        # Filter packs
│   ├── triage/        # Relevance scoring
│   └── validator/      # OCSF validation
├── patterns/            # 133 YAML pattern files
│   └── auto/          # Auto-generated patterns
├── schemas/            # OCSF v1.3 schemas
├── filters/           # Built-in filter packs
├── tests/            # Test suite
└── docs/            # Documentation
```