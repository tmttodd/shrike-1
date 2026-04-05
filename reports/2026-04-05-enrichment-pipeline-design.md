# Shrike Enrichment Pipeline Design (v0.5)

**Status**: Design Proposal  
**Author**: Architect Agent  
**Date**: 2026-04-05  

---

## 1. Problem Statement

Normalized OCSF events lack **context** that makes them actionable:

- `src_endpoint.ip: "185.220.101.42"` → What is this IP?
- `user.name: "jsmith"` → Which department? What's their risk score?
- `dst_endpoint.ip: "10.0.1.50"` → What asset is this? Criticality?

Without enrichment, detection engineers spend hours looking up context manually.

---

## 2. Proposed Solution

A modular enrichment pipeline that attaches context to OCSF events:

```
Raw OCSF Event
      │
      ├─► GeoIP Enricher ────────────────┐
      │   (MaxMind GeoIP2)               │
      │   → country, ASN, org            │
      │                                  │
      ├─► Threat Intel Enricher ─────────┤
      │   (STIX/TAXII feeds)             │
      │   → known-bad IPs, domains       │
      │                                  │
      ├─► Asset Context Enricher ────────┤
      │   (CMDB/Asset DB)                │
      │   → owner, criticality, env      │
      │                                  │
      ├─► User Context Enricher ─────────┤
      │   (HR/IdP integration)           │
      │   → department, role, risk       │
      │                                  │
      ▼                                  │
Enriched OCSF Event ←────────────────────┘
```

---

## 3. Architecture

### Module Structure

```
shrike/enrich/
├── __init__.py
├── enrichment_engine.py       # Orchestrator
├── enrichers/
│   ├── __init__.py
│   ├── base.py                # Abstract Enricher ABC
│   ├── geoip.py               # MaxMind GeoIP2
│   ├── threat_intel.py        # STIX/TAXII, commercial APIs
│   ├── asset_db.py            # CMDB integration
│   ├── user_db.py             # IdP/HR integration
│   └── custom.py              # User-defined enrichers
├── cache/
│   ├── __init__.py
│   ├── memory_cache.py        # In-memory LRU
│   └── redis_cache.py         # Distributed cache
└── config/
    └── enrichment_config.py   # Config schema
```

### Enrichment Flow

```python
@dataclass
class EnrichmentResult:
    event: dict              # Enriched OCSF event
    enrichments: dict        # Per-enricher results
    cache_hit_rate: float    # Efficiency metric
    latency_ms: float        # Total enrichment time


class EnrichmentEngine:
    """Orchestrates enrichment pipeline."""

    def __init__(self, config: EnrichmentConfig):
        self._enrichers = self._load_enrichers(config)
        self._cache = self._create_cache(config.cache)

    def enrich(self, event: dict) -> EnrichmentResult:
        """Enrich a single OCSF event."""
        for enricher in self._enrichers:
            if enricher.should_enrich(event):
                enrichment = self._cache.get(enricher.key(event))
                if enrichment is None:
                    enrichment = enricher.enrich(event)
                    self._cache.set(enricher.key(event), enrichment)
                event = enricher.attach(event, enrichment)

        return EnrichmentResult(...)
```

---

## 4. Enricher Specifications

### GeoIP Enricher

**Input**: `src_endpoint.ip`, `dst_endpoint.ip`  
**Output**: Country, City, ASN, Organization

```yaml
geoip:
  enabled: true
  database_path: /usr/share/GeoIP/GeoLite2-City.mmdb
  asn_database_path: /usr/share/GeoIP/GeoLite2-ASN.mmdb
  timeout_ms: 50
  cache_ttl_seconds: 86400  # 24 hours
```

**Field additions**:
```json
{
  "src_endpoint": {
    "ip": "185.220.101.42",
    "geo": {
      "country_code": "DE",
      "city": "Frankfurt",
      "latitude": 50.1109,
      "longitude": 8.682
    },
    "asn": {
      "number": 24940,
      "org": "Hetzner Online GmbH"
    }
  }
}
```

### Threat Intel Enricher

**Input**: IPs, domains, hashes  
**Output**: Known-bad status, threat categories

```yaml
threat_intel:
  enabled: true
  sources:
    - type: "stix_taxii"
      url: "https://taxii.example.com/api/"
      collection_id: "abc-123"
      credentials_ref: "threat_intel_api_key"

    - type: "commercial_api"
      provider: "virustotal"  # or "talos", "spamhaus"
      api_key_ref: "vt_api_key"

    - type: "open_source"
      feeds:
        - url: "https://rules.emergingthreats.net/open/suricata/emerging-ip.rules"
          refresh_hours: 24

  cache_ttl_seconds: 3600  # 1 hour
  timeout_ms: 200
```

**Field additions**:
```json
{
  "src_endpoint": {
    "ip": "185.220.101.42",
    "threat_intel": {
      "is_known_bad": true,
      "categories": ["tor_exit_node", "malware_c2"],
      "sources": ["abuse.ch", "virustotal"],
      "first_seen": "2024-01-15T00:00:00Z",
      "last_seen": "2026-04-05T00:00:00Z",
      "confidence": 0.95
    }
  }
}
```

### Asset Context Enricher

**Input**: IP, hostname  
**Output**: Owner, criticality, environment, tags

```yaml
asset_db:
  enabled: true
  type: "cmdb_api"  # or "sql", "redis", "custom"
  endpoint: "https://cmdb.internal/api/v1/assets"
  query_timeout_ms: 100
  cache_ttl_seconds: 43200  # 12 hours

  # Field mappings
  mappings:
    ip_field: "src_endpoint.ip"
    hostname_field: "device.hostname"
    output_prefix: "asset."
```

**Field additions**:
```json
{
  "asset": {
    "owner": "john.smith@example.com",
    "department": "Engineering",
    "criticality": "high",
    "environment": "production",
    "tags": ["web-server", "pci-scope"],
    "os": "Ubuntu 22.04",
    "asset_id": "srv-web-042"
  }
}
```

### User Context Enricher

**Input**: `user.name`, `user.uid`  
**Output**: Department, role, risk score, employment status

```yaml
user_db:
  enabled: true
  type: "idp_api"  # or "hr_system", "sql", "ldap"
  provider: "okta"  # or "azure_ad", "ping_identity"
  endpoint: "https://example.okta.com/api/v1/users"
  api_key_ref: "okta_api_key"
  query_timeout_ms: 100
  cache_ttl_seconds: 21600  # 6 hours

  # Risk scoring config
  risk_scoring:
    enabled: true
    factors:
      - field: "employment_status"
        weights:
          active: 0.0
          terminated: 1.0
          leave_of_absence: 0.8

      - field: "privileged_access"
        weights:
          true: 0.5
          false: 0.0
```

**Field additions**:
```json
{
  "user": {
    "name": "jsmith",
    "context": {
      "department": "Engineering",
      "title": "Senior Developer",
      "employment_status": "active",
      "manager": "sjohnson",
      "risk_score": 0.15,
      "privileged_access": false,
      "mfa_enabled": true
    }
  }
}
```

---

## 5. Configuration Schema

```python
@dataclass
class EnrichmentConfig:
    """Configuration for enrichment pipeline."""

    # Global settings
    enabled: bool = True
    parallel_enrichment: bool = True  # Run enrichers concurrently
    total_timeout_ms: int = 1000  # Max total enrichment time

    # Cache config
    cache: CacheConfig = field(default_factory=CacheConfig)

    # Per-enricher config
    geoip: GeoIPConfig | None = None
    threat_intel: ThreatIntelConfig | None = None
    asset_db: AssetDBConfig | None = None
    user_db: UserDBConfig | None = None

    # Custom enrichers
    custom: list[CustomEnricherConfig] = field(default_factory=list)
```

---

## 6. Performance Considerations

### Caching Strategy

| Enricher | Cache TTL | Cache Size | Eviction |
|----------|-----------|------------|----------|
| GeoIP | 24 hours | 1M entries | LRU |
| Threat Intel | 1 hour | 5M entries | LRU |
| Asset DB | 12 hours | 500K entries | LRU |
| User DB | 6 hours | 1M entries | LRU |

### Parallel vs. Sequential

```yaml
# Parallel (default)
parallel_enrichment: true
# Pros: Lower latency (fastest path)
# Cons: Harder to debug, partial failures possible

# Sequential
parallel_enrichment: false
order: [geoip, threat_intel, asset_db, user_db]
# Pros: Deterministic, easier debugging
# Cons: Higher latency (sum of all enrichers)
```

### Fallback Behavior

```yaml
fallback:
  on_timeout: "skip"  # or "partial", "fail"
  on_error: "continue"  # or "fail", "retry"
  max_retries: 2
  retry_backoff_ms: 100
```

---

## 7. Implementation Timeline

| Phase | Component | Duration | Dependencies |
|-------|-----------|----------|--------------|
| 1 | Core engine + cache | Week 1 | None |
| 2 | GeoIP enricher | Week 1 | Core engine |
| 3 | Threat intel enricher | Week 2-3 | Core engine |
| 4 | Asset DB enricher | Week 3 | Core engine |
| 5 | User DB enricher | Week 4 | Core engine |
| 6 | Custom enricher framework | Week 5 | All enrichers |

---

## 8. Success Metrics

| Metric | Target |
|--------|--------|
| **Enrichment Latency** | <100ms (p99) for cached, <500ms (p99) uncached |
| **Cache Hit Rate** | ≥90% for GeoIP/User, ≥70% for Threat Intel |
| **Enrichment Coverage** | ≥80% of events enriched with ≥1 context type |
| **Throughput** | ≥10K events/sec with all enrichers enabled |

---

## 9. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| External API timeouts | High latency | Timeout per enricher, fallback to skip |
| Cache memory pressure | OOM | LRU eviction, size limits |
| CMDB/IdP auth failures | No enrichment | Credential rotation, health checks |
| GeoIP DB outdated | Wrong location | Auto-download updates, version tracking |

---

**END OF DESIGN DOCUMENT**
