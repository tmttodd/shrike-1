# Auto-Generated Patterns

Patterns in this directory are auto-generated from external sources, primarily Splunkbase Technical Add-ons (TAs).

## Sources

| File | Source | Description |
|------|--------|-------------|
| `microsoft_windows.yaml` | Splunkbase TA: ta_microsoft_windows | Windows Event Log |
| `paloalto.yaml` | Splunkbase TA: TA-paloalto | Palo Alto Networks firewalls |
| `pfsense.yaml` | pfSense | pfSense firewall logs |
| `routeros.yaml` | Mikrotik RouterOS | RouterOS devices |
| `trellix_epo.yaml` | Splunkbase TA: trellix_epo | Trellix ePolicy Orchestrator |
| `trendmicro_email.yaml` | Splunkbase TA: trendmicro_email | Trend Micro email security |
| `windns.yaml` | Splunkbase TA: ms_windows_dns | Windows DNS server |

## Status

**Active** — these patterns are maintained and updated when source TAs are updated.

## Maintenance

Auto-generated patterns are regenerated when:
1. Source TA releases a new version
2. Shrike team runs the regeneration script

Do not manually edit files in this directory. To update:
1. Update the source TA
2. Run the regeneration script
3. Submit PR with updated patterns

## Regeneration Script

```bash
# Regenerate all auto patterns
./scripts/regenerate_auto_patterns.py
```

## Verification

Auto-generated patterns are tested in CI to ensure they:
1. Load without errors
2. Match sample logs from the source product
3. Produce valid OCSF output