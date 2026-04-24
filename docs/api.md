# Shrike API Reference

Shrike exposes a REST API on port `8080` for log normalization and routing. All endpoints return JSON unless noted otherwise.

## Endpoints

### POST /v1/ingest

Normalize logs and route to configured destinations.

**Request:**

```json
{
  "logs": ["string", ...]
}
```

- `logs`: array of 1–10,000 log lines as strings.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `Authorization` | Conditional | `Bearer <token>` when `INGEST_API_KEY` is set |
| `X-Forwarded-For` | No | Client IP, used for `src_endpoint.ip` on extracted events |

**Response 200 — Accepted:**

```json
{
  "accepted": 2,
  "total": 2,
  "normalized": 2
}
```

**Error Responses:**

| Status | Meaning |
|--------|---------|
| 400 | Destination rejected events (permanent failure, bad data) |
| 401 | Missing or invalid Bearer token |
| 413 | Request body exceeds 10 MB |
| 422 | Validation error (malformed JSON or schema violation) |
| 507 | All destinations at WAL capacity |

---

### POST /v1/normalize

Normalize logs without routing to any destination. Useful for testing and preview.

**Request:**

Same as `/v1/ingest`.

**Response 200:**

```json
{
  "events": [
    { /* OCSF event */ },
    { /* OCSF event */ }
  ]
}
```

**Error Responses:**

| Status | Meaning |
|--------|---------|
| 400 | No logs provided |
| 422 | Validation error |

---

### POST /v1/batch

Batch normalize and route logs to specific destinations, overriding the default configuration.

**Request:**

```json
{
  "logs": ["string", ...],
  "destinations": ["splunk_hec", "file_jsonl"]
}
```

- `logs`: array of log lines (1–10,000).
- `destinations`: optional. If omitted, uses destinations from `SHRIKE_DESTINATIONS`.

**Response 200:**

```json
{
  "accepted": 2,
  "results": {
    "splunk_hec": {"accepted": 2, "rejected": 0},
    "file_jsonl": {"accepted": 2, "rejected": 0}
  }
}
```

---

### GET /health

Liveness probe. Reports whether the process is alive and the health of each destination.

**Response 200:**

```json
{
  "status": "healthy",
  "pipeline": "active",
  "destinations": {
    "splunk_hec": {"healthy": true, "pending": 0, "disk_usage_mb": 0.0},
    "file_jsonl": {"healthy": true, "pending": 0, "disk_usage_mb": 0.0}
  }
}
```

- `status`: `"healthy"` or `"degraded"` (one or more destinations unhealthy).
- `pipeline`: `"active"` (fully operational) or `"passthrough"` (accepting logs but degraded).

---

### GET /ready

Readiness probe. Reports whether the service can accept traffic.

**Response 200:**

```json
{"ready": true}
```

**Response 503:**

```json
{"ready": false, "reason": "pipeline initializing"}
```

---

### GET /metrics

Prometheus-format metrics endpoint. Returns `text/plain`.

**Response 200:**

```
# HELP shrike_events_accepted_total Events accepted by destination
# TYPE shrike_events_accepted_total counter
shrike_events_accepted_total{dest="splunk_hec"} 1234
# HELP shrike_wal_pending Pending events in WAL
# TYPE shrike_wal_pending gauge
shrike_wal_pending{dest="splunk_hec"} 0
```

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_DESTINATIONS` | `file_jsonl` | Comma-separated list of destinations (`splunk_hec`, `file_jsonl`) |
| `SHRIKE_MODE` | `full` | `full` (server + OTel Collector) or `forwarder` (API only) |
| `SHRIKE_WAL_DIR` | `/data/wal` | Write-ahead log storage directory |
| `SHRIKE_WAL_MAX_MB` | `500` | Maximum WAL size per destination in MB |
| `SHRIKE_FILE_OUTPUT_DIR` | `/data/output` | Output directory for file_jsonl destination |
| `SPLUNK_HEC_URL` | — | Splunk HEC endpoint URL |
| `SPLUNK_HEC_TOKEN` | — | Splunk HEC authentication token |
| `SHRIKE_SPLUNK_TLS_VERIFY` | `true` | Verify Splunk TLS certificate |
| `INGEST_API_KEY` | — | Bearer token for ingest endpoints (empty = open) |
| `SHRIKE_LLM_URL` | — | OpenAI-compatible API URL for LLM extraction tiers |
| `SHRIKE_LLM_MODEL` | — | Model name for LLM extraction |
| `SHRIKE_LLM_API_KEY` | — | API key for LLM endpoint |
| `SHRIKE_CLASSIFIER_MODEL` | `auto` | Path to OCSF classifier model (auto-discovered if not set) |
| `SHRIKE_NER_MODEL` | `auto` | Path to NER model (auto-discovered if not set) |
