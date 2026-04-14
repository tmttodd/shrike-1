---
description: Task — Audit secrets management for exposure and compliance
globs:
  - "**/*"
---

# Task: Security Audit — Secrets

**Agent**: Auditor
**Trigger**: On-demand, monthly scheduled, or after secrets-related incident
**Risk Level**: AUTO (read-only audit)
**Estimated Duration**: 15-30 minutes

## Prerequisites

- Access to OpenBao (vault CLI or Admin API)
- SSH access to Docker hosts (for container env inspection)
- See `CLAUDE.md` Authority & Access section for credential access guidance

## Procedure

### Step 1: List all secret paths in OpenBao

```bash
export VAULT_ADDR="https://openbao.themillertribe-int.org"
vault kv list secret/stacks/
vault kv list secret/services/
```

### Step 2: Check for secrets leaked into environment variables

```bash
# For each container, check if env vars contain hardcoded secrets
# (should reference OpenBao, not contain values directly)
ssh tmiller@192.168.20.15 "for c in \$(sudo docker ps --format '{{.Names}}'); do echo '=== \$c ==='; sudo docker inspect \$c --format '{{json .Config.Env}}' | jq -r '.[]' | grep -i -E 'key=|token=|password=|secret=' | head -5; done"
```

### Step 3: Verify AppRole/JWT auth policies

```bash
vault policy list
vault auth list
# Check JWT role bindings for GitLab CI
vault read auth/jwt/role/gitlab-ci
```

### Step 4: Check token TTLs and orphaned tokens

```bash
vault token lookup  # Check own token expiry
# Admin API for token inventory (if available)
curl -s "https://admin-api.themillertribe-int.org/secrets?path=stacks" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" | jq '.metadata'
```

### Step 5: Check .env files in GitOps repo for leaked secrets

```bash
# Scan for potential secrets in committed files
grep -rn -i 'password\|secret\|token\|api_key' ~/Documents/Claude/repos/homelab-gitops/stacks/ \
  --include='*.env*' --include='*.yml' | grep -v '.env.template' | grep -v '#'
```

### Step 6: Verify 1Password Connect integration

```bash
ssh tmiller@192.168.20.15 "sudo docker logs onepassword-connect --tail 20"
```

## Scoring

| Finding | Risk Level | Priority |
|---------|-----------|----------|
| Secret value hardcoded in compose/env file | CRITICAL | Immediate remediation |
| Secret in env var but not from OpenBao | HIGH | Plan migration |
| Token with no TTL (never expires) | MEDIUM | Schedule rotation |
| Unused secret path (orphaned) | LOW | Clean up |
| Missing AppRole for a service | MEDIUM | Create policy |

## Report

Write to: `reports/YYYY-MM-DD-auditor-secrets-audit.md`
