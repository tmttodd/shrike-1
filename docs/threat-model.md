# Shrike Threat Model

## Overview

Shrike is a security data platform that normalizes raw logs into OCSF format. This document outlines the security architecture, trust boundaries, and identified threats.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     External Sources                         │
│  (Syslog, HTTP API, OTLP, File inputs, Docker logs)         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Trust Boundary 1                         │
│              Input Validation & Sanitization                │
│  - Max log size: 64KB                                       │
│  - Max batch size: 10,000 events                            │
│  - Gzip bomb protection (100MB limit)                       │
│  - Auth required for HTTP endpoints (API key)               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Shrike Runtime (Untrusted)                 │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Format      │  │ Classification│  │ 6-Tier           │   │
│  │ Detection   │  │ (Optional ML) │  │ Extraction       │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ OCSF        │  │ Destination  │  │ WAL (Write-Ahead │   │
│  │ Validation  │  │ Router       │  │ Log)             │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Trust Boundary 2                         │
│              Output Validation & Routing                    │
│  - Schema validation before output                          │
│  - Destination-specific authentication                      │
│  - WAL-backed delivery (at-least-once)                      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  External Destinations                      │
│  (Splunk, S3, File JSONL, Webhooks, Forwarders)            │
└─────────────────────────────────────────────────────────────┘
```

## Trust Boundaries

### Trust Boundary 1: Input Layer
**Untrusted → Trusted**

All external inputs are considered untrusted until validated:
- **HTTP API** (`/v1/ingest`, `/v1/logs`)
- **Syslog** (port 1514 TCP/UDP)
- **OTLP** (gRPC 4317, HTTP 4318)
- **File inputs** (Docker logs, local files)

**Controls:**
- Request size limits (64KB per log, 10K per batch)
- Gzip decompression bomb protection (100MB max)
- API key authentication for HTTP endpoints
- Input sanitization (no shell injection, SQL injection)

### Trust Boundary 2: Output Layer
**Trusted → Semi-Trusted**

Normalized OCSF events are considered trusted internally, but destinations may have varying security postures.

**Controls:**
- OCSF schema validation before output
- TLS verification for Splunk HEC (configurable)
- Destination-specific authentication tokens
- WAL-backed delivery with retry logic

## Identified Threats

### T1: Malformed Input Attacks

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T1.1 | Gzip bomb (decompression bomb) | DoS (memory exhaustion) | Low | 100MB decompression limit | ✅ Implemented |
| T1.2 | Oversized batch (10K+ events) | DoS (memory/CPU) | Low | Hard limit at 10K events/batch | ✅ Implemented |
| T1.3 | Oversized individual log | DoS (memory) | Low | 64KB per log limit | ✅ Implemented |
| T1.4 | Malformed JSON/syslog | Crash/exception | Medium | Try/catch with graceful degradation | ✅ Implemented |
| T1.5 | Injection attacks (SQL, shell) | RCE, data exfil | Low | No shell execution, parameterized queries | ✅ Implemented |

### T2: Authentication & Authorization

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T2.1 | Unauthenticated API access | Data injection | Medium | API key required for HTTP endpoints | ✅ Implemented |
| T2.2 | API key leakage | Unauthorized access | Medium | Secrets via env vars, not hardcoded | ✅ Implemented |
| T2.3 | Replay attacks | Duplicate events | Low | Event timestamps, WAL deduplication | ⚠️ Partial |
| T2.4 | Man-in-the-middle | Data interception | Medium | TLS for Splunk HEC (configurable) | ✅ Implemented |

### T3: Data Integrity

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T3.1 | Event tampering in transit | Data corruption | Medium | TLS, WAL checksums | ✅ Implemented |
| T3.2 | WAL corruption | Data loss | Low | WAL compaction with cursor validation | ✅ Implemented |
| T3.3 | Schema validation bypass | Invalid data downstream | Low | Mandatory OCSF validation | ✅ Implemented |
| T3.4 | Clock skew (timestamp issues) | Incorrect event ordering | Low | Server-side timestamp normalization | ✅ Implemented |

### T4: Resource Exhaustion

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T4.1 | Memory exhaustion (large events) | DoS | Low | Stream processing, no full buffering | ✅ Implemented |
| T4.2 | Disk exhaustion (WAL) | DoS, data loss | Medium | WAL size limits, rotation, alerts | ✅ Implemented |
| T4.3 | CPU exhaustion (complex extraction) | DoS | Low | Tiered extraction (fast paths first) | ✅ Implemented |
| T4.4 | Connection exhaustion | DoS | Low | Connection pooling, timeouts | ✅ Implemented |

### T5: Supply Chain

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T5.1 | Malicious dependencies | RCE, data theft | Low | pip-audit scanning, pinned versions | ✅ Implemented |
| T5.2 | Compromised ML models | Incorrect classification | Medium | Local models only, no runtime downloads | ✅ Implemented |
| T5.3 | Vulnerable base image | Container escape | Low | Regular base image updates | ⚠️ TODO |

### T6: Privacy & Compliance

| ID | Threat | Impact | Likelihood | Mitigation | Status |
|----|--------|--------|------------|------------|--------|
| T6.1 | PII leakage in logs | Compliance violation | Medium | Field masking (configurable) | ⚠️ TODO |
| T6.2 | Unencrypted storage | Data breach | Medium | WAL encryption (optional) | ⚠️ TODO |
| T6.3 | Audit log tampering | Compliance failure | Low | Write-once storage, checksums | ⚠️ Partial |

## Security Controls Summary

### Implemented ✅
- Input validation (size limits, format checks)
- Gzip bomb protection
- API key authentication
- TLS support for destinations
- WAL-backed delivery (at-least-once)
- OCSF schema validation
- Dependency vulnerability scanning (pip-audit)
- SAST scanning (Bandit)
- Local-only ML model loading

### Partial ⚠️
- Replay attack detection (basic timestamp checks)
- Audit log integrity (no cryptographic signing)
- PII detection/masking (not implemented)

### TODO 📋
- Base image vulnerability scanning
- PII field masking
- WAL encryption at rest
- Event signing for audit trails
- Rate limiting per API key

## Security Testing

### Automated Scans
```bash
# SAST (run in CI)
bandit -r shrike/ -f txt

# Dependency vulnerability scan (run in CI)
.venv/bin/pip-audit -r requirements.lock

# Tests (run in CI)
pytest tests/ -v
```

### Manual Testing
- Penetration testing of HTTP API endpoints
- Fuzz testing of format detectors
- Load testing for DoS resistance
- ML model integrity verification

## Incident Response

### Detection
- Monitor for abnormal event volumes
- Alert on WAL size thresholds
- Track authentication failures
- Log all configuration changes

### Response
1. **Input attack**: Enable strict rate limiting, block source IP
2. **Authentication breach**: Rotate API keys, audit access logs
3. **Data corruption**: Restore from WAL, investigate source
4. **Resource exhaustion**: Scale resources, enable throttling

## Compliance Mapping

| Standard | Requirement | Shrike Implementation |
|----------|-------------|----------------------|
| **PCI DSS** | Log integrity | WAL, schema validation |
| **SOC 2** | Access controls | API key authentication |
| **GDPR** | Data minimization | Field masking (TODO) |
| **HIPAA** | Audit trails | WAL, event timestamps |

## Revision History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2026-04-14 | 1.0 | Initial threat model | Shrike Team |
