# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Is Shrike

Shrike is an open-source security data platform that normalizes raw logs into [OCSF v1.3](https://ocsf.io) and routes them where they belong.

Feed it **syslog**, **JSON**, **CEF**, **LEEF**, or any of **14 detected formats**. Get back structured, validated, schema-compliant events — routed to your SIEM, observability stack, or archive.

**Any log in. Normalized OCSF out.**

## Repository Structure

```
shrike/
├── shrike/                    # Main package
│   ├── runtime.py             # FastAPI server + OTel lifecycle
│   ├── pipeline.py            # Normalization pipeline (detect → classify → extract → validate)
│   ├── collector/             # Embedded OpenTelemetry Collector
│   ├── classifier/            # ML log classifier (45 OCSF classes)
│   ├── detector/              # Format detection (14 formats)
│   ├── extractor/             # 6-tier extraction engine
│   ├── destinations/          # Splunk HEC, File JSONL, extensible
│   ├── evaluate/              # Quality evaluation framework
│   ├── filter/                # Filter pack engine
│   ├── triage/                # Relevance scoring
│   └── validator/             # OCSF schema validation
├── patterns/                  # 133 YAML pattern files (50+ vendors)
├── filters/                   # Built-in filter packs
├── schemas/                   # OCSF v1.3 schemas
├── tests/                     # Test suite
├── scripts/
│   ├── download_models.sh     # Download ML models via git-lfs
│   └── evaluate.py            # 9-dimension quality evaluation
├── Dockerfile                 # Multi-stage production build
└── docker-compose.yml         # Single-container deployment
```

## Development Commands

### Setup
```bash
git clone https://github.com/overlabbed-com/shrike.git && cd shrike

# Install git-lfs for ML models (optional — pattern-only mode works without them)
brew install git-lfs
git lfs install
./scripts/download_models.sh

# Install dependencies
pip install -e ".[dev]"
```

### Running the Server
```bash
# Docker Compose (recommended — includes OTel Collector)
docker compose up -d

# Verify it's running
curl -s http://localhost:8080/health | python3 -m json.tool
```

### Running Tests
```bash
pytest tests/ -v
```

### Running a Single Test
```bash
pytest tests/test_pipeline.py -v
```

### Quality Evaluation
```bash
python scripts/evaluate.py  # 9-dimension quality evaluation on 22,739 logs
```

## Architecture

### Extraction Engine — 6 Tiers

The engine cascades from fastest to most thorough until it gets a quality result:

| Tier | Method | Speed | What It Does |
|------|--------|-------|--------------|
| **0** | Fingerprint cache | `O(1)` | Exact match from prior extractions |
| **1** | Pattern library | `<1ms` | 2,052 YAML patterns + 698 field aliases |
| **1.5a** | NER | `~50ms` | SecureBERT entity extraction |
| **1.5b** | Template miner | `~1ms` | Drain3 auto-learned templates |
| **2** | Pre-parse + LLM | `~200ms` | Structured field mapping |
| **3** | Full LLM | `~750ms` | Complete extraction |

**Self-improving**: Every log processed teaches the cache and template miner, making future extractions faster.

### Ingestion Interfaces

| Interface | Port | Protocol |
|-----------|------|----------|
| **HTTP API** | `8080` | `POST /v1/ingest` |
| **Syslog** | `1514` | TCP / UDP |
| **OTLP** | `4317` / `4318` | gRPC / HTTP |

An embedded OpenTelemetry Collector handles syslog and OTLP, with batching and backpressure built in.

### Destination Routing

Events route to one or more destinations. Each uses a **write-ahead log** for delivery guarantees.

| Destination | Routing Strategy |
|-------------|-----------------|
| **Splunk HEC** | Per OCSF class → dedicated indexes (`ocsf-authentication`, `ocsf-ssh-activity`, ...) |
| **File JSONL** | Per OCSF category → directories (`iam/`, `network_activity/`, `system_activity/`) |

The destination interface is extensible — see [`shrike/destinations/base.py`](shrike/destinations/base.py).

## OCSF Event Classes

Shrike classifies logs into **45 OCSF classes** across these categories:

- **IAM**: Authentication, Authorization, Account Management
- **Network Activity**: Connection, DNS, File Transfer
- **System Activity**: Process, Device Config Change, Audit Log
- **Security Findings**: Threat Detection, Malware, Vulnerability
- **Incident Response**: Incident Creation, Investigation

## Adding Patterns

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

Ships with **133 pattern files** covering **50+ vendors** out of the box.

## Filter Packs

YAML filter packs control what reaches each destination:

| Pack | Purpose |
|------|---------|
| `all-pass` | Everything through (default) |
| `security-focused` | Security-relevant events only |
| `noise-reduction` | Drop known-noisy patterns |
| `pci-dss` | PCI DSS compliance scope |

## CLI Reference

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

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SHRIKE_MODE` | `full` | `full` (server + OTel) or `pipeline` (API only) |
| `SHRIKE_DESTINATIONS` | `file_jsonl` | `splunk_hec`, `file_jsonl` (comma-separated) |
| `SPLUNK_HEC_URL` | — | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | — | Splunk HEC token |
| `FILE_OUTPUT_DIR` | `/data/output` | JSONL output path |
| `SHRIKE_WAL_DIR` | `/data/wal` | Write-ahead log path |
| `SHRIKE_WAL_MAX_MB` | `500` | WAL rollover size |
| `SHRIKE_CLASSIFIER_MODEL` | Auto-discovered | Path to OCSF classifier model |
| `SHRIKE_NER_MODEL` | Auto-discovered | Path to NER model |
| `SHRIKE_LLM_URL` | — | OpenAI-compatible API for LLM extraction |
| `SHRIKE_LLM_MODEL` | — | Model name for LLM extraction |
| `SHRIKE_LLM_API_KEY` | — | API key for LLM endpoint (if required) |

## LLM Extraction (Optional)

Shrike's extraction engine has 6 tiers. Tiers 0 through 1.5 are local (patterns, NER, template mining) and need no external services. Tiers 2 and 3 call an **OpenAI-compatible API** for LLM-assisted extraction.

**Any OpenAI-compatible endpoint works** — Ollama, vLLM, LiteLLM, OpenAI, etc.

```bash
# Ollama with fine-tuned shrike-extractor (recommended)
docker run -d -p 11434:11434 ollama/ollama
docker exec ollama ollama pull overlabbed/shrike-extractor

export SHRIKE_LLM_URL=http://localhost:11434/v1
export SHRIKE_LLM_MODEL=overlabbed/shrike-extractor

# Or use any general-purpose model
export SHRIKE_LLM_URL=http://localhost:11434/v1
export SHRIKE_LLM_MODEL=llama3.2:3b

# OpenAI
export SHRIKE_LLM_URL=https://api.openai.com/v1
export SHRIKE_LLM_MODEL=gpt-4o-mini
export SHRIKE_LLM_API_KEY=sk-...
```

## Quality Metrics

Measured on 22,739 logs from 134+ vendors:

| Metric | Result |
|--------|--------|
| **Classification accuracy** | 98.9% across 45 OCSF classes |
| **Useful extraction** (3+ fields) | 61.8% |
| **Type fidelity** | 97.6% |
| **Observables coverage** | 88.2% |

## Code Style

- Python 3.12+
- Line length: 100 (ruff)
- Type hints preferred
- Tests for all new functionality

## License

MIT License
