---
description: Task — Investigate and respond to an infrastructure incident
globs:
  - "**/*"
---

# Task: Incident Response

**Agent**: Responder
**Trigger**: Alert from Sentinel, Herald notification, or Todd reports an issue
**Risk Level**: NOTIFY (safe remediation), APPROVE (anything beyond restarts)
**Estimated Duration**: 5-60 minutes depending on severity

## Prerequisites

- SSH access to Docker hosts
- See `CLAUDE.md` Authority & Access section for SSH guidance

## Procedure

### Step 1: Assess the situation

```bash
# Quick status check
ssh tmiller@192.168.20.15 "sudo docker ps --filter status=exited --filter status=restarting"
ssh tmiller@192.168.20.16 "sudo docker ps --filter status=exited --filter status=restarting"
```

### Step 2: Gather logs from affected service

```bash
ssh tmiller@<host> "sudo docker logs <container> --tail 200 --since 15m"
```

### Step 3: Check resource state

```bash
ssh tmiller@<host> "free -h; df -h; uptime"
ssh tmiller@<host> "nvidia-smi"  # If GPU-related
```

### Step 4: Attempt safe remediation

**Non-critical container restart** (AUTO):
```bash
ssh tmiller@<host> "sudo docker restart <container>"
# Wait 30 seconds, verify
ssh tmiller@<host> "sudo docker ps --filter name=<container>"
```

**Critical container restart** (NOTIFY — tell Todd):
Critical containers: LiteLLM, Authentik, PostgreSQL, GitLab, Prefect, Home Assistant
```bash
ssh tmiller@<host> "sudo docker restart <container>"
# Immediately notify Todd
```

### Step 5: Escalation (if needed)

If 2 restart attempts fail, or issue involves data/config:
- **STOP all remediation**
- Document what was tried and what happened
- Escalate to Todd with full context

### Step 6: Document the incident

Write incident report with:
- Timeline of events
- Root cause analysis (or best hypothesis)
- Actions taken
- Outcome
- Recommendations to prevent recurrence

## Report

Write to: `reports/YYYY-MM-DD-responder-incident-report.md`
