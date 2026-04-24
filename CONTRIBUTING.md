# Contributing to Shrike

Thank you for interest in contributing. This guide covers development setup, code standards, the pattern contribution workflow, and the PR process.

Shrike normalizes raw logs into [OCSF v1.3](https://ocsf.io) events. Contributions fall into two categories:

- **Code changes** -- extraction engine, classification, destinations, CLI, server
- **Pattern additions** -- YAML files teaching Shrike how to parse new log formats

Both are welcome. Pattern contributions are the fastest path to impact.

---

## Development Setup

### Prerequisites

- Python 3.12+
- Docker (optional, for running the full server with OTel Collector)

### Clone and Install

```bash
git clone https://github.com/overlabbed-com/shrike.git && cd shrike

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

### ML Models (Optional)

Shrike ships with two ML models (~830 MB) for classification and NER, tracked via Git LFS. Pattern-only mode works without them, but classification accuracy drops from ~99% to rule-based only.

```bash
# Install git-lfs if needed
brew install git-lfs   # or: apt-get install git-lfs
git lfs install

# Download models
./scripts/download_models.sh
```

### Running the Server

```bash
# Full server with OTel Collector (recommended)
docker compose up -d

# Verify
curl -s http://localhost:8080/health | python3 -m json.tool

# API-only mode (no syslog/OTLP, no Docker)
SHRIKE_MODE=pipeline python -m shrike
```

---

## Running Tests

```bash
# Full suite
pytest tests/ -v

# Single file
pytest tests/test_pipeline.py -v

# Single test
pytest tests/test_pipeline.py::test_extract_syslog -v

# With coverage
pytest tests/ -v --cov=shrike --cov-report=term-missing
```

Tests use `pytest-asyncio` in auto mode. Async test functions are detected automatically.

### Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── fixtures/                # Sample log data
├── test_*.py                # Unit tests by module
├── detect/                  # Format detection tests
├── destinations/            # Destination tests
├── integration/             # End-to-end tests
└── benchmark/               # Performance benchmarks
```

---

## Code Style

Shrike uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting. Configuration lives in `pyproject.toml`.

### Rules

| Setting | Value |
|---------|-------|
| Line length | 100 |
| Target version | py312 |
| Selected rules | `E`, `F`, `I`, `N`, `S`, `W`, `UP` |

### Running Ruff

```bash
# Check for issues
ruff check .

# Auto-fix what can be fixed
ruff check . --fix

# Format
ruff format .
```

### Standards

- **Type hints** on all function signatures. Use `typing` module for complex types.
- **No bare `except:`** -- catch specific exceptions. Use `except Exception as e:` at most.
- **No string concatenation** for SQL, shell commands, or HTML. Use parameterized queries or f-strings with validated input.
- **One responsibility per function.** Max 50 lines, max 5 parameters.
- **Follow existing conventions** in the file you are editing. Match naming, imports, and docstring style.
- **Tests are not optional.** Every new feature needs tests. Bug fixes need regression tests.

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

Examples:

```
feat(extractor): add tier-1.5b template miner
fix(classifier): handle empty log lines gracefully
docs: add contributing guide
test(detector): add cisco asa syslog patterns
refactor(pipeline): extract validation step into own module
```

---

## Pattern Contribution Workflow

Patterns are YAML files in the `patterns/` directory. Each file teaches Shrike how to extract structured fields from a specific vendor or product's logs.

Shrike ships with 133 pattern files covering 50+ vendors out of the box.

### Pattern File Structure

Create a new file at `patterns/<source>.yaml`:

```yaml
source: my_vendor
description: My Vendor product log patterns
version: 1
patterns:
  - name: my_vendor_auth_success
    match:
      log_format: [syslog_bsd]
      regex: 'myapp\[\d+\]:\s+login\s+success\s+user=(?P<user>\S+)\s+from=(?P<src_ip>\S+)'
    ocsf_class_uid: 3002
    ocsf_class_name: Authentication
    static:
      activity_id: 1
      activity_name: "Login"
      severity_id: 1
      category_uid: 3
      category_name: "IAM"
    field_map:
      user: user
      src_ip: src_endpoint.ip
```

### Required Fields

| Field | Description |
|-------|-------------|
| `source` | Vendor or product identifier (lowercase, underscores) |
| `description` | Human-readable description |
| `version` | Pattern file version (start at 1) |
| `patterns[].name` | Unique pattern name within the file |
| `patterns[].match.log_format` | List of log formats this pattern applies to |
| `patterns[].match.regex` | Regex with named capture groups |
| `patterns[].ocsf_class_uid` | OCSF class UID (see mapping below) |
| `patterns[].ocsf_class_name` | OCSF class name |

### Optional Fields

| Field | Description |
|-------|-------------|
| `patterns[].static` | Fixed OCSF fields applied to every match (activity, severity, category) |
| `patterns[].field_map` | Maps regex capture group names to OCSF event field paths |

### Supported Log Formats

The `match.log_format` field accepts any of Shrike's 14 detected formats:

`syslog_bsd`, `syslog_rfc3164`, `syslog_rfc5424`, `json`, `cef`, `leef`, `csv`, `apache_combined`, `apache_common`, `nginx`, `json_lines`, `kinesis_firehose`, `cloudwatch`, `custom`

### Field Mapping

The `field_map` maps regex capture group names to OCSF event field paths using dot notation:

```yaml
field_map:
  user: user                           # top-level field
  src_ip: src_endpoint.ip              # nested field
  src_port: src_endpoint.port
  proto: connection_info.protocol_name
```

Type coercion is automatic: numeric strings become integers, `true`/`false` become booleans, IP addresses are validated.

### Testing a Pattern

```bash
# Test against a log file
echo '%ASA-5-302013: Built inbound TCP connection 1234567 for outside:10.0.0.1/54321 to inside:192.168.1.10/443' | shrike --format json

# Run the full test suite to verify no regressions
pytest tests/ -v

# Run the quality evaluation
python scripts/evaluate.py
```

### OCSF Class Mapping

Shrike classifies logs into 45 OCSF classes across 7 categories. Use the correct UID and class name for your pattern:

#### IAM (Category UID: 3)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Authentication | 3002 | Login attempts, SSO events, MFA |
| Authorization | 3003 | Permission checks, access grants |
| Account Management | 3001 | User create, modify, delete, disable |

#### Network Activity (Category UID: 4)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Network Activity | 4001 | Firewall allows/denies, connections, DNS |
| DHCP Activity | 4002 | Lease assignments, renewals |
| DNS Activity | 4003 | Queries, responses, zone transfers |
| File Transfer | 4004 | FTP, SFTP, SCP transfers |

#### System Activity (Category UID: 1)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Process | 1001 | Process start, stop, creation |
| Device Config Change | 1002 | Config modifications, restarts |
| Audit Log | 1003 | System audit events |
| Endpoint Discovery | 1004 | Asset inventory, device detection |
| File | 1005 | File create, modify, delete |
| Registry | 1006 | Registry key changes |
| SSH Activity | 1007 | SSH connections, commands |
| User | 1008 | Login, logout, session events |

#### Security Findings (Category UID: 5)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Threat Detection | 5001 | IDS/IPS alerts, SIEM detections |
| Malware | 5002 | Antivirus detections, quarantines |
| Vulnerability | 5003 | Scan results, CVE findings |

#### Incident Response (Category UID: 6)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Incident Creation | 6001 | New security incidents |
| Investigation | 6002 | Investigator actions |

#### Data Store Activity (Category UID: 2)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Database Activity | 2001 | Queries, schema changes |

#### Email Activity (Category UID: 7)

| Class | UID | Typical Logs |
|-------|-----|-------------|
| Email | 7001 | Send, receive, spam filter |

> **Tip:** When unsure about the right class, look at existing patterns in `patterns/` for similar products. Search for `ocsf_class_uid` in files that handle similar log types.

### Pattern Submission Checklist

- [ ] Pattern file follows the YAML structure above
- [ ] Regex uses named capture groups (`(?P<name>...)`)
- [ ] `ocsf_class_uid` and `ocsf_class_name` match the correct OCSF class
- [ ] At least one sample log line is included in `tests/fixtures/`
- [ ] A test verifies the pattern extracts expected fields
- [ ] `pytest tests/ -v` passes with no regressions
- [ ] `ruff check .` and `ruff format .` report no issues

---

## Pull Request Requirements

Every PR must meet these requirements before merge:

### Mandatory

- [ ] **Tests pass** -- `pytest tests/ -v` exits 0
- [ ] **No coverage regression** -- new code is covered, existing coverage does not drop
- [ ] **Ruff clean** -- `ruff check .` and `ruff format --check .` pass
- [ ] **Commit messages** follow Conventional Commits format
- [ ] **Branch name** describes the change: `feat/add-paloalto-patterns`, `fix/extractor-null-handling`

### For Code Changes

- [ ] Type hints on all new functions
- [ ] Docstrings on public functions
- [ ] No hardcoded secrets or credentials
- [ ] Error handling catches specific exceptions

### For Pattern Changes

- [ ] Pattern validated against real sample logs
- [ ] OCSF class mapping reviewed against the table above
- [ ] Test fixture added with representative log samples
- [ ] `source` field is lowercase with underscores

### PR Template

```markdown
## Summary

What changed and why.

## Type

- [ ] Code change
- [ ] Pattern addition/update
- [ ] Documentation
- [ ] Other

## Test Plan

- [ ] `pytest tests/ -v` passes
- [ ] `ruff check .` passes
- [ ] Coverage not regressed
- [ ] Manual testing (describe steps)

## Pattern Details (if applicable)

- Vendor:
- OCSF class:
- Sample log: (paste one anonymized line)
- Fields extracted: (list the field_map keys)
```

---

## Quality Evaluation

Shrike includes a 9-dimension quality evaluation script. Run it after significant changes to the extraction or classification pipeline:

```bash
python scripts/evaluate.py
```

This processes 22,739 logs from 134+ vendors and reports on classification accuracy, extraction completeness, type fidelity, and observable coverage. Target metrics:

| Metric | Target |
|--------|--------|
| Classification accuracy | >= 98% |
| Useful extraction (3+ fields) | >= 60% |
| Type fidelity | >= 95% |
| Observables coverage | >= 85% |

---

## Getting Help

- Open an [issue](https://github.com/overlabbed-com/shrike/issues) for questions or bug reports
- For pattern contributions unsure about OCSF mapping, reference existing `patterns/` files for similar products
