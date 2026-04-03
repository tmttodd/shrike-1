<div align="center">
<img src="docs/assets/shrike-wordmark.png" alt="Shrike" width="360" />
<br/>
<b>Any log in. Normalized OCSF out.</b>
<br/><br/>
<a href="https://github.com/overlabbed-com/shrike/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build" /></a>
<a href="https://github.com/overlabbed-com/shrike/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License" /></a>
<a href="https://ocsf.io"><img src="https://img.shields.io/badge/OCSF-v1.3-purple?style=flat-square" alt="OCSF v1.3" /></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+" /></a>
<a href="https://hub.docker.com"><img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" /></a>
<br/><br/>
<a href="#quick-start">Quick Start</a> ·
<a href="#how-it-works">How It Works</a> ·
<a href="#deployment">Deployment</a> ·
<a href="#development">Development</a> ·
<a href="https://overlabbed.com">Blog</a>
</div>

---

Shrike is an open-source security data platform that normalizes raw logs into [OCSF v1.3](https://ocsf.io) and routes them where they belong.

Feed it **syslog**, **JSON**, **CEF**, **LEEF**, or any of **14 detected formats**. Get back structured, validated, schema-compliant events — routed to your SIEM, observability stack, or archive.

<br/>

## Quick Start

### Prerequisites

Shrike ships with two ML models (~830MB) tracked via [Git LFS](https://git-lfs.com). If you have `git-lfs` installed, they download automatically on clone. If not:

```bash
# Option A: Install git-lfs, then clone
brew install git-lfs   # or: apt-get install git-lfs
git lfs install

# Option B: Clone first, download models separately
git clone https://github.com/overlabbed-com/shrike.git && cd shrike
./scripts/download_models.sh
```

> Without models, Shrike still works in **pattern-only mode** (1,390 YAML patterns, no ML classification or NER).

### Option 1: Docker (recommended)

The fastest way to get Shrike running with all features — syslog ingestion, OTLP, HTTP API, and destination routing.

```bash
git clone https://github.com/overlabbed-com/shrike.git && cd shrike
docker compose up -d
```

Verify it's running:

```bash
curl -s http://localhost:8080/health | python3 -m json.tool
```

Send a log via the HTTP API:

```bash
curl -s -X POST http://localhost:8080/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{"logs": ["Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22"]}'
```

Or point your syslog sources at port `1514`:

```bash
# From any host with rsyslog
echo '*.* @@shrike-host:1514' >> /etc/rsyslog.d/50-shrike.conf
systemctl restart rsyslog
```

### Option 2: pip install

Install Shrike as a Python package for CLI usage or to embed the normalization pipeline in your own code.

```bash
pip install -e ".[dev]"
```

Normalize a single log from the command line:

```bash
echo 'Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22' | shrike
```

Process a log file:

```bash
shrike --input /var/log/auth.log --format summary
```

Use it in Python:

```python
from shrike.pipeline import ShrikePipeline

pipe = ShrikePipeline()
result = pipe.process("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22")

print(result.class_name)   # "Authentication"
print(result.class_uid)    # 3002
print(result.event)        # Full OCSF event dict
```

### Example output

```json
{
  "class_uid": 3002,
  "class_name": "Authentication",
  "activity_id": 1,
  "status": "Success",
  "user": "admin",
  "src_endpoint": { "ip": "10.0.0.1", "port": 22 },
  "auth_protocol": "password",
  "observables": [
    { "name": "src_endpoint.ip", "type": "IP Address", "value": "10.0.0.1" },
    { "name": "user", "type": "User Name", "value": "admin" }
  ]
}
```

<br/>

## How It Works

```
           ┌─────────────────────────────────────────┐
           │                                         │
  Syslog ──┤                                         ├──→ Splunk (by OCSF class)
           │   Detect → Classify → Extract → Validate│
  HTTP ────┤                                         ├──→ File JSONL (by category)
           │                                         │
  OTLP ────┤                                         ├──→ ... (extensible)
           │                                         │
           └─────────────────────────────────────────┘
```

### Ingestion

Three ways to get logs in:

| Interface | Port | Protocol |
|-----------|------|----------|
| **HTTP API** | `8080` | `POST /v1/ingest` |
| **Syslog** | `1514` | TCP / UDP |
| **OTLP** | `4317` / `4318` | gRPC / HTTP |

An embedded [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) handles syslog and OTLP, with batching and backpressure built in.

### Extraction Engine

Six tiers, from instant to thorough. The engine cascades until it gets a quality result.

| Tier | Method | Speed | What It Does |
|------|--------|-------|--------------|
| **0** | Fingerprint cache | `O(1)` | Exact match from prior extractions |
| **1** | Pattern library | `<1ms` | 1,390 YAML patterns + 698 field aliases |
| **1.5a** | NER | `~50ms` | SecureBERT entity extraction |
| **1.5b** | Template miner | `~1ms` | Drain3 auto-learned templates |
| **2** | Pre-parse + LLM | `~200ms` | Structured field mapping |
| **3** | Full LLM | `~750ms` | Complete extraction |

> **Self-improving**: Every log processed teaches the cache and template miner, making future extractions faster.

### Destinations

Events route to one or more destinations. Each uses a **write-ahead log** for delivery guarantees.

| Destination | Routing Strategy |
|-------------|-----------------|
| **Splunk HEC** | Per OCSF class → dedicated indexes (`ocsf-authentication`, `ocsf-ssh-activity`, ...) |
| **File JSONL** | Per OCSF category → directories (`iam/`, `network_activity/`, `system_activity/`) |

The destination interface is easy to extend — see [`shrike/destinations/base.py`](shrike/destinations/base.py).

<br/>

## Deployment

### Docker Compose (recommended)

```bash
docker compose up -d
curl http://localhost:8080/health
```

Single container. Non-root. ML models are optional — pattern-only mode works without them.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_MODE` | `full` | `full` (server + OTel) or `pipeline` (API only) |
| `SHRIKE_DESTINATIONS` | `file_jsonl` | `splunk_hec`, `file_jsonl` (comma-separated) |
| `SPLUNK_HEC_URL` | — | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | — | Splunk HEC token |
| `FILE_OUTPUT_DIR` | `/data/output` | JSONL output path |
| `SHRIKE_WAL_DIR` | `/data/wal` | Write-ahead log path |
| `SHRIKE_CLASSIFIER_MODEL` | Auto-discovered | Path to OCSF classifier model dir |
| `SHRIKE_NER_MODEL` | Auto-discovered | Path to NER entity extraction model dir |
| `SHRIKE_LLM_URL` | — | OpenAI-compatible API base URL for LLM extraction (Tiers 2 & 3) |
| `SHRIKE_LLM_MODEL` | — | Model name for LLM extraction |
| `SHRIKE_LLM_API_KEY` | — | API key for LLM endpoint (if required) |

### LLM Extraction (optional)

Shrike's extraction engine has 6 tiers. Tiers 0 through 1.5 are local (patterns, NER, template mining) and need no external services. Tiers 2 and 3 call an **OpenAI-compatible API** for LLM-assisted extraction of fields that patterns can't reach.

Without an LLM configured, Shrike still extracts fields using patterns (1,390 rules), NER (SecureBERT), and auto-learned templates. LLM tiers activate only when earlier tiers produce incomplete results.

**Any OpenAI-compatible endpoint works** — Ollama, vLLM, LiteLLM, OpenAI, etc.

```bash
# Ollama (local, free)
docker run -d -p 11434:11434 ollama/ollama
docker exec ollama ollama pull llama3.2:3b

export SHRIKE_LLM_URL=http://localhost:11434/v1
export SHRIKE_LLM_MODEL=llama3.2:3b

# OpenAI
export SHRIKE_LLM_URL=https://api.openai.com/v1
export SHRIKE_LLM_MODEL=gpt-4o-mini
export SHRIKE_LLM_API_KEY=sk-...

# vLLM / LiteLLM / any OpenAI-compatible server
export SHRIKE_LLM_URL=http://your-server:8000/v1
export SHRIKE_LLM_MODEL=your-model-name
```

In Docker Compose, add to the `environment` section:

```yaml
environment:
  SHRIKE_LLM_URL: http://host.docker.internal:11434/v1
  SHRIKE_LLM_MODEL: llama3.2:3b
```

| Tier | Method | Needs LLM? | Typical Coverage |
|------|--------|-----------|-----------------|
| 0 | Fingerprint cache | No | Exact matches from prior runs |
| 1 | Pattern library | No | ~60% of logs (known formats) |
| 1.5a | NER (SecureBERT) | No | Entity extraction from freetext |
| 1.5b | Template miner | No | Auto-learned log templates |
| 2 | Pre-parse + LLM | **Yes** | Structured field mapping |
| 3 | Full LLM | **Yes** | Unknown formats, complex logs |

### CLI Reference

```bash
# Normalize logs from stdin
cat /var/log/syslog | shrike

# Process a file with summary output
shrike --input access.log --format summary

# Detect formats only (no extraction)
shrike --input mixed.log --detect-only

# Classify only (detection + classification, no extraction)
shrike --input mixed.log --classify-only

# Apply a filter pack
shrike --input noisy.log --filter noise-reduction

# Full JSON array output
shrike --input auth.log --format json
```

<br/>

## Extending Shrike

### Adding Patterns

Patterns are YAML. Each one teaches Shrike how to extract fields from a specific log format.

```yaml
# patterns/my_vendor.yaml
source: my_vendor
patterns:
  - name: my_vendor_auth
    match:
      log_format: [syslog_bsd]
      regex: 'myapp\[\d+\]:\s+login\s+(?P<result>success|fail)\s+user=(?P<user>\S+)\s+from=(?P<ip>\S+)'
    ocsf_class_uid: 3002
    ocsf_class_name: Authentication
    field_map:
      user: user
      ip: src_endpoint.ip
      result: status
```

Ships with **67 pattern files** covering **50+ vendors** out of the box.

### Filter Packs

YAML filter packs control what reaches each destination:

| Pack | Purpose |
|------|---------|
| `all-pass` | Everything through (default) |
| `security-focused` | Security-relevant events only |
| `noise-reduction` | Drop known-noisy patterns |
| `pci-dss` | PCI DSS compliance scope |

<br/>

## Development

```bash
git clone https://github.com/overlabbed-com/shrike.git && cd shrike
pip install -e ".[dev]"
pytest tests/              # 209 tests
python scripts/evaluate.py # 9-dimension quality evaluation
```

### Quality Metrics

Measured on 22,739 logs from 134+ vendors:

| Metric | Result |
|--------|--------|
| **Classification accuracy** | 98.9% across 45 OCSF classes |
| **Useful extraction** (3+ fields) | 61.8% |
| **Type fidelity** | 97.6% |
| **Observables coverage** | 88.2% |

### Project Structure

```
shrike/
├── shrike/
│   ├── runtime.py            # FastAPI server + OTel lifecycle
│   ├── pipeline.py           # Normalization pipeline
│   ├── collector/            # Embedded OTel Collector
│   ├── classifier/           # ML log classifier (45 classes)
│   ├── detector/             # Format detection (14 formats)
│   ├── extractor/            # 6-tier extraction engine
│   ├── destinations/         # Splunk HEC, File JSONL, ...
│   ├── evaluate/             # Quality framework
│   ├── filter/               # Filter pack engine
│   ├── triage/               # Relevance scoring
│   └── validator/            # OCSF schema validation
├── patterns/                 # 67 YAML pattern files
├── filters/                  # Built-in filter packs
├── schemas/                  # OCSF v1.3 schemas
├── tests/                    # 209 tests
├── Dockerfile                # Multi-stage production build
└── docker-compose.yml
```

<br/>

## Roadmap

- [ ] S3 / MinIO destination (Parquet, partitioned by class)
- [ ] Triage-based routing (relevance score → destination)
- [ ] Correlation engine (multi-event detection)
- [ ] Enrichment pipeline (GeoIP, threat intel, asset context)
- [ ] Sigma rule integration
- [ ] Web dashboard

<br/>

## License

[MIT](LICENSE)

---

<p align="center">
  <sub>Built by <a href="https://overlabbed.com">overlabbed</a></sub>
</p>
