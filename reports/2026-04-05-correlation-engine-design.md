# Shrike Correlation Engine Design (v0.4)

**Status**: Design Proposal  
**Author**: Architect Agent  
**Date**: 2026-04-05  
**Version**: v0.4  

---

## 1. Problem Statement

Shrike currently normalizes logs into OCSF format and routes them via triage to destinations. However, **single-event detection misses attack patterns** that span multiple events:

- **Brute force**: 5 failed logins from same IP in 60 seconds
- **Lateral movement**: SSH from compromised host to multiple internal systems
- **Data exfiltration**: Large outbound transfers after privilege escalation
- **Reconnaissance**: Sequential port scans across subnet

These require **cross-event correlation** that single-event analysis cannot provide.

---

## 2. Proposed Solution

A three-layer correlation system:

```
Security Events (from triage)
       │
       ├─► Time Series Builder ──► FM4TS Anomaly Detection
       │                              │
       │                              └─► Behavioral Anomalies
       │
       ├─► Sigma Rule Engine ─────────────┐
       │                                      │
       │                              Correlation Alerts
       │
       └─► Pattern Correlator ──────────────┘
           (multi-event sequences)
```

### Layer 1: FM4TS Anomaly Detection

**Cisco Foundation Model for Time Series** detects statistical anomalies in event rates:

- **Per-observable time series**: Group by IP, user, hostname, etc.
- **Baseline learning**: Unsupervised - learns "normal" from the stream
- **Anomaly scoring**: Flags deviations without labeled attack data

**Use cases**:
- Sudden spike in authentication failures from single IP
- Unusual DNS query volume from a workstation
- Abnormal after-hours API activity

### Layer 2: Sigma Rule Engine

**Sigma rules** (SIEM-agnostic detection rules) compiled to OCSF field mappings:

```yaml
# Example Sigma rule
title: Suspicious PowerShell Execution
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    process_name: 'powershell.exe'
    cmd_line|contains|all:
      - '-enc'
      - 'DownloadString'
  condition: selection
level: high
```

**Benefits**:
- Community-curated rule library (1000+ Sigma rules)
- Vendor-neutral format
- Maps to OCSF fields automatically

### Layer 3: Pattern Correlator

**Stateful multi-event correlation** for attack sequences:

```python
# Brute Force Detection Pattern
BRUTE_FORCE = {
    "name": "Brute Force Attack",
    "window_seconds": 300,
    "correlation_key": ["src_endpoint.ip", "user.name"],
    "sequence": [
        {"class_uid": 3002, "status_id": 9},  # Failed auth
        {"class_uid": 3002, "status_id": 9},  # Failed auth
        {"class_uid": 3002, "status_id": 9},  # Failed auth
        {"class_uid": 3002, "status_id": 1},  # Successful auth
    ],
    "threshold": 4,
    "mitre_technique": "T1110.001",  # Brute Force: Password Guessing
}
```

---

## 3. Architecture

### Module Structure

```
shrike/detect/
├── __init__.py
├── correlation_engine.py      # Main orchestrator
├── timeseries/
│   ├── __init__.py
│   ├── fm4ts_adapter.py       # FM4TS integration
│   ├── window_buffer.py       # Sliding window implementation
│   └── anomaly_scorer.py      # Anomaly score calculation
├── sigma/
│   ├── __init__.py
│   ├── rule_loader.py         # Parse Sigma YAML
│   ├── ocsf_mapper.py         # Sigma → OCSF field mapping
│   └── rule_engine.py         # Real-time matching
└── patterns/
    ├── __init__.py
    ├── sequence_matcher.py    # Multi-event sequence detection
    ├── attack_patterns.py     # MITRE ATT&CK patterns
    └── state_tracker.py       # Per-entity state management
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      shrike.normalize                            │
│              (Detect → Classify → Extract → Validate)            │
└───────────────────────────┬─────────────────────────────────────┘
                            │ OCSF Event
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    shrike.triage                                 │
│              (Relevance scoring + routing)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ Security Events (score >= 0.7)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   shrike.detect                                  │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   TimeSeries │  │    Sigma     │  │  Pattern     │          │
│  │   Builder    │──│    Engine    │──│  Correlator  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                  │                  │                  │
│         └──────────────────┴──────────────────┘                  │
│                            │                                     │
│                            ▼                                     │
│              ┌─────────────────────────┐                        │
│              │   Correlation Alert     │                        │
│              │  - alert_id             │                        │
│              │  - correlation_type     │                        │
│              │  - severity             │                        │
│              │  - matched_rules/patterns│                       │
│              │  - observable_context   │                        │
│              │  - mitre_techniques     │                        │
│              └─────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │      Destinations           │
              │  - Splunk (alerts)          │
              │  - SIEM integration         │
              │  - Slack/PagerDuty          │
              └─────────────────────────────┘
```

---

## 4. Implementation Phases

### Phase 1: Sigma Rule Engine (Week 1-2)

**Deliverables**:
- Sigma YAML parser and validator
- OCSF field mapping layer
- Real-time rule matching engine
- Built-in rule library (50 high-value rules)

**Dependencies**:
- `sigma-core` Python package for Sigma parsing
- Existing OCSF field schema

### Phase 2: Pattern Correlator (Week 3-4)

**Deliverables**:
- State tracker per observable (IP, user, hostname)
- Sequence matching algorithm
- 10 pre-built attack patterns (MITRE ATT&CK)
- Window-based event buffering

**Dependencies**:
- Phase 1 complete
- Redis or SQLite for state persistence (optional)

### Phase 3: FM4TS Integration (Week 5-6)

**Deliverables**:
- FM4TS model wrapper
- Time series window buffer
- Anomaly scoring API
- Baseline adaptation mechanism

**Dependencies**:
- FM4TS Python SDK or ONNX model
- Phase 2 state tracking infrastructure

---

## 5. Configuration

```yaml
# shrike-detect-config.yaml
correlation:
  enabled: true
  
  sigma:
    rule_dirs:
      - /etc/shrike/sigma/rules/
      - /etc/shrike/sigma/custom/
    update_interval_hours: 24
    severity_threshold: medium
    
  patterns:
    load_builtin: true
    custom_patterns:
      - /etc/shrike/patterns/my-pattern.yaml
      
  timeseries:
    enabled: true
    window_seconds: 3600  # 1 hour sliding window
    baseline_days: 7      # Learn baseline over 7 days
    anomaly_threshold: 3.0  # Standard deviations
    
  output:
    destinations:
      - splunk_hec
      - slack_webhook
    alert_format: ocsf_incident
```

---

## 6. API Design

### Ingestion

```python
from shrike.detect.correlation_engine import CorrelationEngine

engine = CorrelationEngine(config_path="/etc/shrike/detect-config.yaml")

# Feed OCSF events
for event in ocsf_event_stream:
    alerts = engine.process(event)
    for alert in alerts:
        route_to_siem(alert)
```

### Alert Structure

```python
@dataclass
class CorrelationAlert:
    alert_id: str                    # UUID
    timestamp: datetime
    correlation_type: str            # "sigma", "pattern", "anomaly"
    severity: str                    # "critical", "high", "medium", "low"
    title: str                       # Human-readable title
    description: str                 # Detailed description
    
    # Matching context
    matched_rules: list[str]         # Sigma rule IDs
    matched_patterns: list[str]      # Pattern IDs
    anomaly_scores: dict[str, float] # Observable → score
    
    # Observable context
    observables: list[dict]          # IPs, users, hosts involved
    event_count: int                 # Events in correlation window
    time_window_start: datetime
    time_window_end: datetime
    
    # MITRE ATT&CK
    mitre_techniques: list[str]      # e.g., ["T1110.001", "T1078"]
    mitre_tactics: list[str]         # e.g., ["TA0006", "TA0004"]
    
    # Raw event references
    event_ids: list[str]             # References to source events
    raw_event_summary: str           # First 500 chars of aggregated events
```

---

## 7. Risk Assessment

### Blast Radius: **Contained**

- New module, doesn't modify existing pipeline
- Can be enabled/disabled via config
- Alerts are additive (don't block event flow)

### Reversibility: **Trivial**

- Disable via config: `correlation.enabled: false`
- No database migrations required
- State can be cleared without data loss

### Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| High CPU from FM4TS | Degraded throughput | Async processing, batch inference |
| False positives from Sigma | Alert fatigue | Tune rules, add suppression |
| Memory from state tracking | OOM crashes | LRU eviction, window limits |
| Sigma rule parsing failures | Silent drops | Validation at load time, logging |

---

## 8. Testing Strategy

### Unit Tests
- Sigma rule parsing and validation
- OCSF field mapping accuracy
- Sequence matching logic
- Time series window calculations

### Integration Tests
- End-to-end alert generation
- Multi-event correlation scenarios
- FM4TS anomaly detection (mocked model)

### Golden Tests
- Known attack patterns produce expected alerts
- False positive scenarios produce no alerts
- Alert structure matches schema

---

## 9. Success Metrics

| Dimension | Target |
|-----------|--------|
| **Detection Rate** | ≥90% of known attack patterns |
| **False Positive Rate** | ≤5% of total alerts |
| **Processing Latency** | <100ms per event (p99) |
| **Memory Footprint** | <512MB for 1M events/hour |
| **Rule Coverage** | 50+ Sigma rules at launch |

---

## 10. Rollback Plan

If issues arise:
1. Set `correlation.enabled: false` in config
2. Restart Shrike server
3. Correlation stops immediately, events flow through normally
4. No data loss (events bypass correlation layer)

---

## 11. Next Steps

1. **Architect**: Finalize design (this document)
2. **Advocate**: Challenge design (see separate challenge report)
3. **Todd**: Approve design
4. **Changemaker**: Create feature branch, implement phases
5. **Scribe**: Update documentation

---

**END OF DESIGN DOCUMENT**
