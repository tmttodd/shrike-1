# Shrike Platform Architecture

> Shrike is a security data platform. Not a log normalizer — a platform.

## Module Map

```
shrike.normalize    Log in → OCSF out        BUILT
shrike.evaluate     9-dimension quality       BUILT
shrike.triage       Event-level relevance     BUILT
shrike.detect       Correlation + anomaly     PLANNED (v0.3)
shrike.enrich       GeoIP + threat intel      PLANNED (v0.4)
```

## Data Flow

```
Raw Logs
  │
  ▼
┌─────────────────────────────────────────────────────────────┐
│ shrike.normalize                                            │
│                                                             │
│  Detect → Classify → Extract → Validate → Enrich → OCSF    │
│  (format)  (class)   (6-tier)  (schema)   (required)        │
│                                                             │
│  Self-improving: fingerprint cache, template miner, alias   │
│  table — every log processed teaches the next extraction    │
└────────────────────────┬────────────────────────────────────┘
                         │ OCSF Events
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ shrike.triage                                               │
│                                                             │
│  Score relevance (0.0-1.0) per event:                       │
│    - Event subtype (activity_id + class_uid)                │
│    - Source reputation (Sysmon=high, healthcheck=low)        │
│    - Field richness (user+IP+cmd_line = relevant)           │
│    - ATT&CK coverage (does this event enable detection?)    │
│                                                             │
│  Reclassify when relevance < 0.3 (wrong class signal)       │
│                                                             │
│  Route:                                                     │
│    Security (0.7+)    → shrike.detect (hot path)            │
│    Operational (0.3+) → ops pipeline (warm path)            │
│    Compliance          → cold archive (S3/glacier)          │
│    Noise (<0.1)       → drop or sample                      │
│                                                             │
│  Every reclassification feeds back to GT quality →           │
│  classifier retraining → fewer reclassifications over time  │
└──────┬──────────┬──────────┬──────────┬─────────────────────┘
       │          │          │          │
       ▼          ▼          ▼          ▼
   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
   │ Detect │ │  Ops   │ │Archive │ │  Drop  │
   │  $$$   │ │   $    │ │   ¢    │ │   0    │
   └────────┘ └────────┘ └────────┘ └────────┘
```

## shrike.triage — The Module That Pays For The Platform

### Why Event-Level Routing

Source-level routing (Cribl model): "Send all Palo Alto logs to Splunk."
Event-level routing (Shrike model): "This Palo Alto event is a critical exploit
detection → Splunk. This Palo Alto event is a heartbeat → drop."

Same source, different events, different value, different cost.

### Relevance Score Components

```python
relevance = weighted_average(
    subtype_score,      # 0.4 weight — is this the RIGHT kind of event for its class?
    field_richness,     # 0.3 weight — does it have security-relevant fields?
    attack_coverage,    # 0.2 weight — does it enable ATT&CK technique detection?
    source_reputation,  # 0.1 weight — is this source known to produce quality data?
)
```

### Reclassification Loop

Events with relevance < 0.3 trigger secondary classification:
1. Try pattern extraction without class constraint (class_uid=0)
2. If patterns match a different class with high confidence → reclassify
3. If no class fits → Base Event (class 0) + "unclassifiable" tag
4. Every reclassification is a GT quality signal → feeds into retraining

### Cost Model

| Tier | Volume | Destination | Cost/GB | Savings vs All-to-SIEM |
|------|--------|-------------|---------|----------------------|
| Security | ~10% | SIEM | $15/GB | — |
| Operational | ~30% | Observability | $3/GB | 80% |
| Compliance | ~40% | Cold archive | $0.02/GB | 99.9% |
| Noise | ~20% | /dev/null | $0 | 100% |

Enterprise at 100M events/day: $450K/mo all-to-SIEM → $45K/mo with triage.

## shrike.detect — Behavioral Detection (v0.3)

### Architecture

```
Security-relevant OCSF events (from triage)
  │
  ├─ Per-observable time series (IP rate, user rate, DNS rate)
  │
  ├─ FM4TS anomaly detection (Cisco Foundation Model for Time Series)
  │   → No labeled attack data needed
  │   → Learns normal from the OCSF stream
  │   → Flags deviations
  │
  ├─ Sigma rule engine (for known detection patterns)
  │   → Sigma YAML → OCSF field mapping → real-time matching
  │
  └─ Correlation engine (multi-event patterns)
      → "5 failed logins from same IP in 60s" = T1110 Brute Force
      → Uses observables[] for cross-event linking
```

### What FM4TS Adds

Single-event detection (shrike.normalize): "This event has suspicious cmd_line."
Behavioral detection (shrike.detect): "This IP has made 500 auth attempts in 30 seconds."

Both are needed. Normalize provides the data quality. Detect provides the pattern recognition.

## shrike.enrich — Context (v0.4)

- GeoIP: IP → country/ASN/org (MaxMind)
- Threat intel: IP/domain/hash → known-bad (STIX/TAXII feeds)
- Asset context: IP/hostname → asset owner, criticality, environment
- User context: username → department, role, risk score

Enrichment attaches CONTEXT to the OCSF event. Triage uses context for routing.
Detect uses context for alert prioritization.

## Evaluation Framework (Cross-Module)

Each module has its own evaluation dimensions:

| Module | Dimensions |
|--------|-----------|
| normalize | breadth, accuracy, schema compliance, type fidelity, observables |
| triage | relevance precision, routing accuracy, reclassification rate, cost savings |
| detect | detection rate, false positive rate, MTTD, ATT&CK coverage |
| enrich | enrichment hit rate, staleness, coverage |

All dimensions flow into a platform-level composite score.
All dimensions have self-improvement loops.
All dimensions have transparency reports (how measured, what failed, why, where to fix).

## Three Measurement Directions (All Modules)

| Direction | What It Measures | Who Cares |
|-----------|-----------------|-----------|
| Inward | Module quality (accuracy, speed, reliability) | Engineering |
| Outward | Source quality (completeness, format, reliability) | Security Engineering |
| Forward | Detection capability (ATT&CK coverage, MTTD, blind spots) | CISO |
