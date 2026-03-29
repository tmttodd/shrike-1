# Shrike

**Any log in. OCSF out. No parsers to write.**

Shrike is a log normalization engine that converts raw logs from any source into structured [OCSF](https://ocsf.io) events. No custom parsers, no regex libraries, no source-specific configuration. Point it at logs and get normalized, enriched, filterable security data.

## The Problem

Every log source speaks its own language. Onboarding a new source into your SIEM means weeks of parser development, field mapping, testing, and maintenance. When the vendor changes their log format, your parser breaks.

Shrike eliminates parser development. It understands log structure through AI — not regex patterns — and maps every field to the OCSF standard automatically.

## How It Works

```
Raw log (any format) ──► Shrike ──► OCSF JSON ──► Your SIEM
```

Multi-stage pipeline, not a single monolithic model:

| Stage | Method | Speed |
|-------|--------|-------|
| **Detect** | Format fingerprinting (regex/heuristic) | <1ms |
| **Classify** | Embedding similarity against OCSF class vectors | ~5ms |
| **Filter** | Configurable filter packs (YAML rules) | <1ms |
| **Extract** | Fine-tuned LLM with class-specific schema injection | ~500ms CPU, ~50ms GPU |
| **Validate** | JSON schema compliance, auto-retry on failure | <1ms |

**~500ms per event on CPU. ~50ms on GPU. Horizontally scalable.**

## Design Principles

- **CPU-first.** Runs on any machine. GPU accelerates but isn't required.
- **OCSF-native.** Output conforms to OCSF v1.3. Every event, every time.
- **No training per source.** Same model handles syslog, CEF, JSON, XML, CSV, Zeek, EVTX, cloud APIs.
- **Filter packs.** Drop noise before it hits your SIEM. Configurable per compliance framework.
- **Cloud-native.** Stateless container. Scale horizontally. K8s, Compose, or bare metal.
- **Schema-injected extraction.** The classifier picks the OCSF class. The extractor gets only that class's field schema. The model never memorizes 650+ fields — it only sees the 10-15 relevant to this event.

## Quick Start

```bash
docker run -p 8080:8080 ghcr.io/tmttodd/shrike:latest

curl -X POST http://localhost:8080/normalize \
  -H "Content-Type: application/json" \
  -d '{"raw_log": "Mar 27 10:15:33 server01 sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2"}'
```

```json
{
  "class_uid": 3002,
  "class_name": "Authentication",
  "severity_id": 2,
  "status": "Failure",
  "user": {"name": "root"},
  "src_endpoint": {"ip": "192.168.1.100", "port": 54321},
  "dst_endpoint": {"hostname": "server01"},
  "metadata": {"version": "1.3.0", "product": {"name": "sshd", "vendor_name": "OpenSSH"}}
}
```

## Filter Packs

```yaml
# filters/pci-dss.yaml
name: PCI-DSS Compliance
rules:
  - keep:
      classes: [3002, 3003, 3005, 4001, 4007, 2001, 2004]
  - keep:
      severity_id: {gte: 3}
  - drop:
      classes: [0]
```

## Architecture

```
┌──────────────────────────────────────────────┐
│                 Shrike Pod                    │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Detector │─►│Classifier│─►│  Filter   │  │
│  │ (regex)  │  │(embed)   │  │  (rules)  │  │
│  └──────────┘  └──────────┘  └───────────┘  │
│                                    │         │
│                                    ▼         │
│              ┌──────────┐  ┌───────────┐     │
│              │Extractor │─►│ Validator │     │
│              │(LLM +    │  │ (schema)  │     │
│              │ schema)  │  └───────────┘     │
│              └──────────┘                    │
│                                              │
│  Models: classifier-embed.onnx (~100MB)      │
│          extractor-3b.gguf (~2GB)            │
│  Config: schemas/ocsf_v1.3/, filters/*.yaml  │
└──────────────────────────────────────────────┘
```

## Tested Sources

40+ log source types including CrowdStrike, SentinelOne, Carbon Black, Palo Alto, Fortinet, Cisco ASA, Okta, Duo, Zeek, Suricata, Sysmon, Windows Security, AWS CloudTrail, GCP Audit, Azure NSG, Linux syslog, Apache, Nginx, DNS, DHCP, Juniper, Arista, PostgreSQL, Kubernetes audit, and more.

## License

TBD
