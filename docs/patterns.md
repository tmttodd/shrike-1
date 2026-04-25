# Pattern Contribution Guide

Patterns teach Shrike how to extract fields from specific log formats. They are YAML files that map regex patterns to OCSF fields.

## Pattern File Structure

```yaml
source: <vendor_name>
description: '<description of what this pattern handles>'
version: 1
auto_generated: true  # Set if auto-generated, omit if manual

patterns:
  - name: <pattern_name>
    match:
      log_format: [syslog_bsd, syslog_ietf, json, cef, leef, ...]
      regex: '<regex with named capture groups>'
    ocsf_class_uid: <OCSF class UID>
    ocsf_class_name: <OCSF class name>
    field_map:
      <regex_group>: <ocsf_field>
      ...
    static:
      <ocsf_field>: <static_value>
```

## Example: SSH Authentication

```yaml
source: openssh
description: 'OpenSSH authentication events'
version: 1
patterns:
  - name: ssh_auth_success
    match:
      log_format: [syslog_bsd]
      regex: 'sshd\[\d+\]: Accepted (?P<auth_method>\w+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)'
    ocsf_class_uid: 3002
    ocsf_class_name: Authentication
    field_map:
      user: user.name
      src_ip: src_endpoint.ip
      src_port: src_endpoint.port
      auth_method: auth_method
    static:
      category_uid: 3
      category_name: Identity & Access Management
```

## Supported Log Formats

| Format | Description |
|-------|-------------|
| `syslog_bsd` | BSD syslog (e.g., `Mar 29 10:00:00 host sshd[123]: ...`) |
| `syslog_ietf` | IETF syslog (RFC 5424) |
| `json` | JSON log lines |
| `cef` | Common Event Format |
| `leef` | Log Event Extended Format |
| `xml` | XML-formatted logs |
| `kvp` | Key-value pairs (`key=value key=value`) |

## OCSF Field Mapping

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `user.name` | String | Username |
| `user.type` | String | `user` or `system` |
| `src_endpoint.ip` | IP Address | Source IP |
| `src_endpoint.port` | Port | Source port |
| `dst_endpoint.ip` | IP Address | Destination IP |
| `dst_endpoint.port` | Port | Destination port |
| `metadata.event_code` | String | Event ID or code |
| `metadata.product.name` | String | Product name |
| `metadata.vendor.name` | String | Vendor name |
| `severity_id` | Integer | 1=low, 2=medium, 3=high, 4=critical |
| `status` | String | `success` or `failure` |

### OCSF Class Reference

**Authentication (category_uid: 3)**:
- `3001` — Entity Account Created
- `3002` — Authentication
- `3003` — Authorization
- `3004` — Account Change

**Network Activity (category_uid: 4)**:
- `4001` — Network Activity
- `4002` — Network Connection
- `4003` — DNS Query

**System Activity (category_uid: 5)**:
- `5001` — Process Started
- `5002` — Device Config Change

## Testing Patterns Locally

### 1. Validate YAML Syntax

```bash
python -c "import yaml; yaml.safe_load(open('patterns/my_vendor.yaml'))"
```

### 2. Test Pattern Matching

```bash
# Using the CLI
echo 'Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22' | shrike --input - --format json
```

### 3. Run the Test Suite

```bash
pytest tests/extractor/test_pattern_extractor.py -v -k my_vendor
```

## Auto-Generated Patterns

Patterns in `patterns/auto/` are generated from Splunkbase TAs and other sources. They are tracked in Git but should not be manually edited.

**Status**: Active — these patterns are maintained by the Shrike team and updated when source TAs change.

## Adding a New Vendor Pattern

1. **Create the pattern file**: `patterns/<vendor>.yaml`
2. **Test with sample logs**: Verify extraction works
3. **Add tests**: Add test cases in `tests/extractor/test_pattern_extractor.py`
4. **Run the full suite**: `pytest tests/ -q`
5. **Submit PR**: Include sample logs and expected extractions

## Pattern Style Guide

1. **One pattern per concern**: Don't combine multiple event types
2. **Use named groups**: `(?P<field_name>regex)` not unnamed `(regex)`
3. **Be specific**: Anchor patterns to reduce false positives
4. **Document edge cases**: Note known variations in description
5. **Test with real data**: Include actual log samples in tests

## Validation

Run pattern validation before submitting PR:

```bash
python -c "
import yaml
from pathlib import Path
from shrike.extractor.pattern_extractor import PatternExtractor

for f in Path('patterns').glob('*.yaml'):
    try:
        data = yaml.safe_load(open(f))
        print(f'Valid: {f.name}')
    except Exception as e:
        print(f'Invalid: {f.name} — {e}')
"