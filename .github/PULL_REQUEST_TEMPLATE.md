# Pull Request Checklist

## Pre-Flight Security Checks

Before merging, ensure all of the following pass:

### ✅ Security Scanning
- [ ] **SAST (Bandit)**: `bandit -r shrike/ -f txt` - No High severity issues
- [ ] **Dependency Audit**: `.venv/bin/pip-audit -r requirements.lock` - No vulnerabilities
- [ ] **Threat Model Review**: Updated `docs/threat-model.md` if new attack surface added

### ✅ Code Quality
- [ ] **All Tests Pass**: `pytest tests/ -v` - 528 tests passing
- [ ] **Benchmarks Pass**: `pytest tests/benchmarks/ -v` - Performance within thresholds
- [ ] **No New Warnings**: Check for Python deprecation warnings
- [ ] **Type Checking**: `mypy shrike/` (if applicable)

### ✅ Documentation
- [ ] **README Updated**: If CLI/API changed
- [ ] **Threat Model Updated**: If new security-relevant code added
- [ ] **ML Dependencies Doc Updated**: If ML behavior changed
- [ ] **Changelog Entry**: Added to `CHANGELOG.md` (if exists)

### ✅ Code Review
- [ ] **At least 1 approval** from team member
- [ ] **Security review** if touching auth, validation, or data handling
- [ ] **No secrets** in code or commit history
- [ ] **Import order** consistent (standard lib → third party → local)

## Changes Summary

### What Changed
<!-- Describe what this PR does and why -->

### Security Impact
<!-- Does this introduce new attack surface? Does it fix a security issue? -->

### Breaking Changes
<!-- Any API, config, or behavior changes that break existing usage? -->

### Testing
<!-- How was this tested? Include load test results if applicable. -->

## Related Issues
- Closes #<!-- issue number -->
