# Correlation Engine Design Challenge

**Status**: Challenge Report  
**Author**: Advocate Agent  
**Date**: 2026-04-05  
**Reviews**: Design doc `2026-04-05-correlation-engine-design.md`

---

## Executive Summary

The correlation engine design is **sound but ambitious**. Three critical concerns need addressing before implementation:

1. **FM4TS dependency risk** - Cisco's model may not be production-ready
2. **State management complexity** - Distributed state is harder than acknowledged
3. **Alert fatigue guarantee missing** - No throttling/de-duplication strategy

---

## Concern 1: FM4TS Dependency Risk

**Severity**: HIGH

### The Problem

The design assumes FM4TS (Cisco Foundation Model for Time Series) is available as a Python SDK or ONNX model. This is **unproven**:

- FM4TS research paper exists (2024)
- No official Python SDK on PyPI
- No ONNX export documented
- Cisco has not announced public release

### Potential Impact

- Phase 3 becomes blocked indefinitely
- Need fallback anomaly detection
- Architecture may need redesign

### Recommended Mitigation

**Option A: Swap to proven alternative**
- Use `statsmodels` (Python, mature)
- Use `pyod` (Python Outlier Detection library)
- Use simple statistical baselines (moving average + std dev)

**Option B: Defer FM4TS, build abstraction**
```python
class AnomalyDetector(ABC):
    @abstractmethod
    def fit(self, series: List[float]) -> None: ...
    @abstractmethod
    def score(self, value: float) -> float: ...

class StatisticalAnomalyDetector(AnomalyDetector):
    """Simple z-score based - available today"""
    pass

class FM4TSAdapter(AnomalyDetector):
    """Swap in when FM4TS becomes available"""
    pass
```

**Recommendation**: Start with Option B. Build the abstraction, implement statistical baseline now, plug in FM4TS later if/when available.

---

## Concern 2: State Management Complexity

**Severity**: MEDIUM

### The Problem

The design mentions "Redis or SQLite for state persistence (optional)" but this is **not optional** for production:

- Pattern correlator needs per-observable state (millions of IPs, users)
- Memory-only state doesn't survive restarts
- Multi-instance deployments need shared state
- SQLite doesn't scale horizontally

### Current Design Gap

```python
# Design shows:
state_tracker: StateTracker  # Where does this store state?

# But doesn't specify:
- How state survives restarts?
- How multiple Shrike instances coordinate?
- What happens when Redis is down?
- How to prune old state (DoS vector)?
```

### Recommended Mitigation

**Explicit state layer design**:
```
shrike/detect/state/
├── backend.py          # Abstract backend (ABC)
├── memory_backend.py   # In-memory (dev/testing only)
├── sqlite_backend.py   # Single-instance production
└── redis_backend.py    # Multi-instance production
```

**State TTL policy**:
- IP state: 24 hours default
- User state: 7 days default
- Auto-prune on each window tick
- Configurable per-observable-type

**Failover behavior**:
- Redis down → fall back to memory (lossy but functional)
- Memory overflow → LRU eviction (drop oldest)
- Log warnings on state loss

---

## Concern 3: Alert Fatigue Guarantee Missing

**Severity**: HIGH

### The Problem

No **alert throttling** or **de-duplication** strategy. Without this:

- Same attack = hundreds of identical alerts
- Sigma rules fire on every matching event
- Pattern correlator emits alert per sequence match
- SIEM gets flooded, operators tune out

### Real-World Example

```
Attack: Brute force from IP 1.2.3.4
- 50 failed logins in 5 minutes
- Sigma rule "Multiple Auth Failures" fires on each failure = 50 alerts
- Pattern correlator matches brute force pattern = 1 alert (good)
- FM4TS detects anomaly = 1 alert (good)

Without de-duplication: 52 alerts for 1 attack
With de-duplication: 1-2 alerts for 1 attack
```

### Recommended Mitigation

**Alert aggregation strategy**:
```python
class AlertAggregator:
    """De-duplicate and aggregate alerts"""

    def __init__(
        self,
        window_seconds: int = 300,      # Group alerts within 5 min
        similarity_threshold: float = 0.9,  # Similarity for grouping
        max_alerts_per_group: int = 100,    # Cap per-group count
    ): ...

    def process(self, alert: CorrelationAlert) -> Optional[AggregatedAlert]:
        """
        Returns aggregated alert if new, None if absorbed into existing.
        """
```

**Suppression rules**:
```yaml
suppressions:
  - name: "Known scanner"
    condition: "src_endpoint.ip IN (scanner_whitelist)"
    action: "drop"

  - name: "Rate limit per rule"
    rule_id: "Sigma_Suspicious_PowerShell"
    max_per_hour: 10
    action: "aggregate"
```

**Alert priority queue**:
- Critical: Immediate (PagerDuty)
- High: Batched every 15 min
- Medium: Batched hourly
- Low: Daily digest

---

## Concern 4: Performance Under Load

**Severity**: MEDIUM

### The Problem

Design targets "<100ms per event (p99)" but doesn't account for:

- FM4TS inference time (unknown, potentially seconds)
- Sigma rule matching (100+ rules × event = ?)
- Pattern state lookups (millions of observables)
- Time series window calculations (sliding window = expensive)

### Back-of-Envelope Calculation

```
100 Sigma rules × 1 event = 100 field lookups + pattern matches
If each rule takes 0.1ms → 10ms total (acceptable)
If each rule takes 1ms → 100ms total (borderline)
If each rule takes 10ms → 1000ms (unacceptable)

Pattern correlator:
1M observables × state lookup = ?
If O(1) hash lookup @ 100ns → 0.1ms (acceptable)
If O(n) scan @ 1μs per lookup → 1s (unacceptable)
```

### Recommended Mitigation

**Performance budgets per component**:
```yaml
performance:
  sigma_matching:
    budget_ms: 20
    rule_count_max: 100

  pattern_matching:
    budget_ms: 30
    observable_cache_size: 1000000

  timeseries:
    budget_ms: 50
    window_size_max: 3600  # 1 hour

  total:
    budget_ms: 100
    async_fallback: true   # If exceeded, queue for async processing
```

**Async fallback**:
- Events that exceed budget go to async queue
- Alerts generated asynchronously
- Lossy but maintains throughput

---

## Concern 5: Testing Coverage Gap

**Severity**: LOW

### The Problem

Testing strategy mentions unit/integration/golden tests but lacks:

- **Load tests**: 10K events/sec throughput
- **Chaos tests**: Redis down, FM4TS timeout, memory pressure
- **Accuracy tests**: Precision/recall on labeled attack dataset

### Recommended Mitigation

**Add to test plan**:
```
tests/detect/
├── load/
│   ├── test_throughput.py       # 10K events/sec target
│   └── test_memory_pressure.py  # OOM under stress
├── chaos/
│   ├── test_redis_down.py       # Graceful degradation
│   └── test_fm4ts_timeout.py    # Timeout handling
└── accuracy/
    └── test_precision_recall.py # Labeled attack dataset
```

**Labeled dataset**:
- Need 1000+ labeled events (attack vs. normal)
- Can use CIC-IDS2017, CSE-CIC-IDS2018 public datasets
- Convert to OCSF format for testing

---

## Revised Success Criteria

Original criteria need tightening:

| Dimension | Original | Revised |
|-----------|----------|---------|
| **Detection Rate** | ≥90% | ≥90% on labeled dataset |
| **False Positive Rate** | ≤5% | ≤5% over 7-day rolling window |
| **Processing Latency** | <100ms (p99) | <100ms (p99), <10ms (p50) |
| **Memory Footprint** | <512MB | <512MB @ 1M events/hr, <1GB @ 10M |
| **Alert De-duplication** | (not specified) | ≥90% reduction vs. raw matches |
| **Uptime** | (not specified) | 99.9% (state backend failures handled) |

---

## Final Recommendation

**APPROVED WITH CONDITIONS**:

1. ✅ **Proceed with Sigma engine** (lowest risk, highest value)
2. ✅ **Proceed with pattern correlator** (state design needs revision per Concern 2)
3. ⚠️ **Defer FM4TS** until availability confirmed, build abstraction layer
4. ⚠️ **Add alert aggregation** before any release
5. ⚠️ **Define state backend strategy** (SQLite vs. Redis decision)

**Timeline adjustment**:
- Phase 1 (Sigma): Week 1-2 → **unchanged**
- Phase 2 (Patterns): Week 3-4 → **extend to Week 5** (state design)
- Phase 3 (FM4TS): Week 5-6 → **defer to v0.5** or swap to statsmodels

---

**END OF CHALLENGE REPORT**
