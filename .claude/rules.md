# Shrike-Specific Governance Rules

These rules augment the root `.claude/rules/` governance framework. They NEVER weaken those policies.

## Project Context

Shrike is a log normalization pipeline that converts raw logs (syslog, JSON, CEF, LEEF) into OCSF v1.3.0 structured events. Critical for security observability infrastructure.

**Key constraints:**
- ML models (~830MB) tracked via Git LFS
- 133 pattern files covering 50+ vendors
- 6-tier extraction engine (cache → patterns → NER → template mining → LLM)
- Write-ahead log for delivery guarantees

## Security Requirements

### Data Handling
- **Never log raw credentials** in ingestion pipeline
- **Sanitize PII** before OCSF transformation (configurable via filter packs)
- **Validate all input** at HTTP API boundary (rate limiting, payload size)
- **TLS required** for all external destinations (Splunk HEC, S3)

### Pattern Safety
- All regex patterns must pass `safe-regex` validation before merge
- Maximum pattern backtracking: 1000 steps
- No `.*` patterns without bounded anchors

### ML Model Integrity
- Models must be signed/verified on load
- Classifier model: 45 OCSF classes, accuracy ≥95%
- NER model: SecureBERT-based, entity types documented

## Quality Gates

| Gate | Tool | Threshold |
|------|------|-----------|
| **Classification accuracy** | `scripts/evaluate.py` | ≥98% on test set |
| **Pattern coverage** | `tests/test_patterns.py` | 100% of vendors documented |
| **OCSF schema validation** | `shrike/validator/` | 100% of events |
| **Performance (Tier 1)** | Benchmark | <1ms per log |
| **Performance (Tier 2+3)** | Benchmark | <1s per log with LLM |

## Development Workflow

### Adding a New Pattern
1. Create `patterns/<vendor>.yaml`
2. Add test case in `tests/test_patterns.py`
3. Verify OCSF class mapping is correct
4. Run `scripts/evaluate.py` to confirm no regression
5. Document vendor in README

### Adding a New Destination
1. Implement `shrike/destinations/<name>.py` extending `BaseDestination`
2. Add write-ahead log support
3. Implement retry logic with exponential backoff
4. Add configuration validation
5. Write integration test with mock destination

### ML Model Updates
1. Train model on expanded dataset
2. Run evaluation suite (9 dimensions)
3. Compare against baseline metrics
4. If accuracy drops >2%, STOP and investigate
5. Version model directory (`models/classifier-v2/`)
6. Update `pyproject.toml` if model format changes

## Testing Requirements

### Unit Tests
- All pattern regexes tested against sample logs
- Field mapping validated against OCSF schema
- Destination write-ahead log durability tested

### Integration Tests
- HTTP API end-to-end (ingest → transform → destination)
- Syslog ingestion (TCP/UDP)
- OTLP receiver (gRPC/HTTP)
- Multi-destination fanout

### Performance Tests
- Throughput: ≥10,000 logs/sec (Tier 0-1 only)
- Latency: p99 <100ms for pattern matching
- Memory: <2GB RSS under load

## OCSF Compliance

All output MUST be OCSF v1.3.0 compliant:
- `class_uid` matches OCSF registry
- `activity_id` within valid range for class
- Required fields present for class
- Field types match schema (string, int, bool, timestamp)

Use `shrike/validator/ocsf_validator.py` to validate before merge.

## Deployment Constraints

- **Container**: Non-root user (UID 1000)
- **Memory limit**: Minimum 4GB RAM for ML features
- **Disk**: WAL directory must have 1GB free minimum
- **Network**: Outbound only (to destinations), no inbound except configured ports

## Failure Modes

| Symptom | Root Cause | Remediation |
|---------|-----------|-------------|
| High latency | LLM Tier 3 saturation | Increase timeout or fallback to Tier 2 |
| WAL overflow | Destination down | Check destination connectivity, increase WAL max |
| Pattern mismatch | Vendor log format changed | Update pattern, add version field |
| ML classification fail | Model corruption | Reload model, verify checksum |
