# Shrike

**Log normalization engine. Any format in, OCSF JSON out.**

Shrike converts raw log lines into structured [OCSF v1.3](https://ocsf.io) events using a multi-tier extraction engine that improves itself over time.

## What It Does

```
Raw log ──► Detect format ──► Classify (OCSF class) ──► Extract fields ──► Validate ──► OCSF JSON
```

```bash
echo 'Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22' | shrike
```

```json
{
  "class_uid": 3002,
  "class_name": "Authentication",
  "activity_id": 1,
  "severity_id": 1,
  "user": "admin",
  "src_endpoint": {"ip": "10.0.0.1", "port": 22},
  "auth_protocol": "password",
  "time": "Mar 29 10:00:00"
}
```

## Current Quality

Measured on 3,128 unseen logs from 134 vendors (no training data overlap):

| Metric | Value |
|--------|-------|
| **Verified extraction** | 36% of logs get 3+ pattern-extracted fields |
| **Classification accuracy** | 98.9% across 45 OCSF classes |
| **Format detection** | 14 log formats auto-detected |
| **Speed** | 200+ logs/sec (pattern engine, CPU only) |
| **Patterns** | 500+ specific extraction patterns |

36% means: on a diverse dataset of 134 security vendors, Shrike produces useful OCSF output for about 1 in 3 logs using only patterns. For common sources (SSH, Windows, FortiGate, DNS, firewall, CEF), the rate is 80-100%. The remaining logs need either new patterns or LLM enrichment.

## What It Doesn't Do

- **Not magic.** Unknown log formats produce class metadata only, not field extraction. You need patterns for your specific vendors.
- **Not a SIEM.** Shrike normalizes logs. It doesn't store, search, alert, or correlate.
- **Not production-hardened.** This is v0.1.0. The API, patterns, and output format will change.

## Install

```bash
pip install shrike
```

For LLM enrichment (Tier 2/3):
```bash
pip install shrike[llm]
```

## Quick Start

**Detect log format:**
```bash
echo '<134>1 2026-03-29T10:00:00Z host app 1234 - - message' | shrike --detect-only
# syslog_rfc5424
```

**Full pipeline (pattern extraction):**
```bash
cat /var/log/auth.log | shrike --format jsonl
```

**With filter:**
```bash
cat logs.txt | shrike --filter security-focused --format summary
```

## Architecture

Five-tier extraction, fastest first:

| Tier | Method | Speed | When |
|------|--------|-------|------|
| **0** | Fingerprint cache | O(1) | Seen this JSON structure before |
| **1** | Pattern library | <1ms | Specific regex/JSON match exists |
| **2** | Pre-parse + LLM | ~200ms | Structured fields exist, need OCSF mapping |
| **3** | Full LLM | ~1.3s | No pattern, no structure |
| **—** | Validator | <1ms | Always runs last |

Tiers 0-1 are CPU-only, no dependencies beyond PyYAML. Tiers 2-3 require an OpenAI-compatible API endpoint (Ollama, vLLM, etc.).

**Self-improving:** Every successful extraction teaches Tier 0. The more logs Shrike sees, the faster it gets.

## Adding a Pattern

Patterns are YAML files in `patterns/`. Each pattern has a match condition and a field map:

```yaml
source: my_app
description: My application logs
version: 1
patterns:
  - name: my_app_auth
    match:
      log_format: [syslog_bsd]
      regex: 'myapp\[\d+\]:\s+login\s+(?P<result>success|fail)\s+user=(?P<user>\S+)\s+from=(?P<ip>\S+)'
    ocsf_class_uid: 3002
    ocsf_class_name: Authentication
    static:
      activity_id: 1
      severity_id: 1
      category_uid: 3
      category_name: "Identity & Access Management"
    field_map:
      user: user
      ip: src_endpoint.ip
      result: status
```

Drop it in `patterns/`, restart Shrike. Every regex named group maps to an OCSF field path.

For JSON logs, use `json_has` and `json_match` instead of regex:

```yaml
    match:
      log_format: [json]
      json_has: ["EventID", "UserName"]
      json_match:
        EventID: 4624
```

## Confidence Scoring

Every extracted field carries a confidence tag:

| Confidence | Meaning |
|-----------|---------|
| `pattern` | Extracted by specific regex or JSON match (highest) |
| `alias` | Mapped via known field name alias table |
| `fuzzy` | Mapped via substring heuristics |
| `embedding` | Mapped via semantic similarity model |
| `cache` | Retrieved from fingerprint cache |
| `llm` | Extracted by LLM (accuracy varies) |

## Project Structure

```
shrike/
  detector/          Format detection (14 formats)
  classifier/        DistilBERT OCSF classifier (98.9%)
  extractor/         5-tier extraction engine
  filter/            YAML filter packs
  validator/         OCSF v1.3 schema validation
  pipeline.py        Synchronous pipeline
  pipeline_async.py  Async pipeline with ring buffer
patterns/            Extraction patterns (YAML)
schemas/             OCSF v1.3 class schemas (JSON)
filters/             Filter pack definitions
scripts/             Quality report, benchmarks
training/            Model training scripts
tests/               93 tests (unit + integration)
```

## Development

```bash
git clone https://github.com/tmttodd/shrike
cd shrike
pip install -e ".[dev]"
pytest tests/
python scripts/quality_report.py
```

## License

MIT
