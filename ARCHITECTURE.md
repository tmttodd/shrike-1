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

## Self-Improving Extraction — The Feedback Loop

Shrike's extraction engine doesn't just process logs — it learns from them. Every
log that passes through makes the next extraction faster and more accurate.

### The Three Learning Systems

```
                        ┌──────────────────────────────┐
                        │     New log arrives           │
                        └──────────┬───────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                     ▼
     ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────┐
     │ Fingerprint      │ │ Template Miner  │ │ Pattern Learner  │
     │ Cache            │ │ (Drain3)        │ │                  │
     │                  │ │                 │ │                  │
     │ JSON structure   │ │ Freetext log    │ │ Pre-parsed       │
     │ → field mapping  │ │ → template      │ │ → verified OCSF  │
     │ O(1) lookup      │ │ → entity types  │ │   field mappings │
     │                  │ │ → OCSF paths    │ │                  │
     └────────┬─────────┘ └────────┬────────┘ └────────┬─────────┘
              │                    │                    │
              │             ┌──────┴──────┐             │
              │             ▼             ▼             │
              │     Instant extraction    │             │
              │     on next match         │             │
              │                           │             │
              └───────────┐   ┌───────────┘             │
                          ▼   ▼                         ▼
                   ┌─────────────────┐        ┌─────────────────┐
                   │ Promotion Gate  │        │ YAML Export      │
                   │ 3+ hits, ≥80%   │───────▶│ Permanent        │
                   │ confidence      │        │ pattern files    │
                   └─────────────────┘        └─────────────────┘
```

**1. Fingerprint Cache** — The JIT compiler for JSON logs.

When a JSON log is extracted by the LLM (Tiers 2-3), the cache stores the
mapping between JSON field names and OCSF field paths. Next time a log with
the same JSON structure arrives, the cached mapping is applied in O(1) — no
LLM call needed. The cache reverse-engineers the mapping automatically by
matching extracted values back to their source fields.

- Keyed by sorted top-level JSON keys + class UID
- Confidence score based on hit count and validation pass rate
- LRU eviction at 10,000 entries, prioritizing low-confidence templates
- Persisted to `data/fingerprint_cache.json` across runs

**2. Template Miner** — Statistical structure discovery for freetext logs.

Drain3 observes raw log traffic and discovers repeating templates — which
parts are static structure and which are variable values. Each variable
position gets classified by entity type (IP, port, username, path, PID)
using regex classifiers, then mapped to OCSF fields via the alias table.

- No pre-written patterns needed — learns from traffic
- Entity classification: 9 types (IP, port, MAC, email, path, hex, timestamp, PID, user)
- Maps entity types → OCSF paths: IP → `src_endpoint.ip`, port → `src_endpoint.port`, etc.
- Persisted to `data/template_cache.json` across runs

**3. Pattern Learner** — Verified field mapping from pre-parsed logs.

Pre-parses a log to extract structured fields, maps each field to an OCSF
path via fuzzy matching or the alias table, then **verifies** that each
mapped value actually appears in the raw log text. Only saves patterns with
3+ verified field mappings. No hallucination — if the value isn't in the
log, it's not in the pattern.

### How the LLM Works Itself Out of a Job

```
  Day 1:  100% of novel JSON logs hit Tier 3 (LLM, ~750ms each)
          │
          │  Cache learns every extraction
          ▼
  Day 2:  70% hit Tier 0 (cache, ~0ms) — same JSON structures seen yesterday
          30% hit Tier 3 (LLM) — new structures
          │
          │  Templates with 3+ hits and ≥80% confidence become promotable
          ▼
  Day 7:  90% hit Tier 0 (cache) or Tier 1 (promoted patterns)
          10% hit Tier 3 (LLM) — truly novel formats
          │
          ▼
  Steady: LLM handles only first-encounter formats
          Cache and patterns handle everything seen before
```

### Promotion: Cache → Permanent Pattern

Templates graduate when they meet three criteria:

| Criterion | Threshold | Why |
|-----------|-----------|-----|
| Hit count | ≥ 3 | Seen enough times to be a real format, not noise |
| Confidence | ≥ 80% | Validation rate proves the mapping is correct |
| Validation passes | ≥ 2 | Independent confirmations that extracted values match source |

Promotable templates can be exported as permanent YAML pattern files via
`cache.get_promotable()` and the pattern learner's YAML export. Once promoted,
they run at Tier 1 speed (<1ms) instead of Tier 0 cache lookup.

### The Feedback Points

Every successful extraction at Tiers 1-3 feeds back into the learning systems:

| Extraction Tier | Feeds Into | What It Learns |
|-----------------|-----------|----------------|
| Tier 1 (Pattern) | Fingerprint cache | JSON field → OCSF mapping for cache hits |
| Tier 1.5b (Template) | Template miner | Variable positions, entity types |
| Tier 2 (Pre-parse + LLM) | Fingerprint cache | LLM's field mapping, validated |
| Tier 3 (Full LLM) | Fingerprint cache | Complete extraction mapping |

The template miner also trains continuously — every log fed to `miner.train()`
refines its template clusters, even if extraction happened at a different tier.

### Persistence

Both caches are memory-resident during a run and persisted to disk:

| Cache | File | Loaded At | Saved At |
|-------|------|-----------|----------|
| Fingerprint cache | `data/fingerprint_cache.json` | Startup | `save_cache()` call |
| Template miner | `data/template_cache.json` | Startup | `save_cache()` call |

The runtime calls `save_cache()` at shutdown to preserve learned state across
restarts. Learned patterns survive container restarts when the data volume is
mounted.

---

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
