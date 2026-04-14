---
description: Task — Detect drift between GitOps repo and running Docker state
globs:
  - "**/*"
---

# Task: Compose Drift Scan

**Agent**: Sentinel
**Trigger**: On-demand, daily via reconciler, or when deployment anomaly suspected
**Risk Level**: AUTO (read-only)
**Estimated Duration**: 5-10 minutes

## Prerequisites

- SSH access to Docker hosts
- Up-to-date clone of homelab-gitops at `~/Documents/Claude/repos/homelab-gitops/`
- See `CLAUDE.md` Authority & Access section for GitOps path guidance

## Procedure

### Step 1: Ensure local repo is current

```bash
cd ~/Documents/Claude/repos/homelab-gitops && git fetch origin && git status
```

### Step 2: For each stack, compare Git compose vs running state

```bash
# Get running image versions on dockp01
ssh tmiller@192.168.20.15 "sudo docker ps --format '{{.Names}}: {{.Image}}'" | sort

# Get image versions from Git compose files
grep -r "image:" ~/Documents/Claude/repos/homelab-gitops/stacks/*/docker-compose.yml | sort
```

### Step 3: Compare environment variables

```bash
# Git-declared env (templates, not secrets)
cat ~/Documents/Claude/repos/homelab-gitops/stacks/<stack>/.env.template

# Running container env (filtered for non-secret vars)
ssh tmiller@192.168.20.15 "sudo docker inspect <container> --format '{{json .Config.Env}}'" | jq -r '.[]' | grep -v -i 'key\|token\|password\|secret'
```

### Step 4: Check for containers not in Git (cowboy deployments)

```bash
# Running compose projects
ssh tmiller@192.168.20.15 "sudo docker compose ls --format json" | jq -r '.[].Name'

# Git-declared stacks
ls ~/Documents/Claude/repos/homelab-gitops/stacks/
```

### Step 5: Check for legacy directories on host

```bash
ssh tmiller@192.168.20.15 "ls /mnt/docker/ | grep -v stacks"
```

## Drift Categories

| Category | Severity | Example |
|----------|----------|---------|
| **Image mismatch** | Medium | Git says v0.15.1, container running v0.14.1 |
| **Missing in Git** | High | Container running but no compose in repo |
| **Missing in runtime** | Medium | Compose in repo but container not running |
| **Config diverged** | Medium | Env var differs between Git and running |
| **Legacy orphan** | Low | Old directories on host, not managed by GitOps |

## Expected Output

Drift report categorized by severity with specific remediation recommendations.

## Report

Write to: `reports/YYYY-MM-DD-sentinel-drift-detection.md`
