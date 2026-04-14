---
description: Task — Check container health across all Docker hosts
globs:
  - "**/*"
---

# Task: Container Health Check

**Agent**: Sentinel
**Trigger**: On-demand, or as first step in any monitoring workflow
**Risk Level**: AUTO (read-only)
**Estimated Duration**: 2-5 minutes

## Prerequisites

- SSH access to Docker hosts (tmtdockp01, tmtdockp02)
- See `CLAUDE.md` Authority & Access section for SSH guidance

## Procedure

### Step 1: Get container status on all hosts

```bash
# dockp01
ssh tmiller@192.168.20.15 "sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' | sort"

# dockp02
ssh tmiller@192.168.20.16 "sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' | sort"
```

### Step 2: Check for unhealthy or restarting containers

```bash
ssh tmiller@192.168.20.15 "sudo docker ps --filter health=unhealthy --filter status=restarting --format '{{.Names}}: {{.Status}}'"
ssh tmiller@192.168.20.16 "sudo docker ps --filter health=unhealthy --filter status=restarting --format '{{.Names}}: {{.Status}}'"
```

### Step 3: Check resource usage

```bash
ssh tmiller@192.168.20.15 "sudo docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' | sort -k2 -t'%' -rn | head -15"
ssh tmiller@192.168.20.16 "sudo docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' | sort -k2 -t'%' -rn | head -15"
```

### Step 4: Check GPU state (AI workloads)

```bash
ssh tmiller@192.168.20.15 "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader"
ssh tmiller@192.168.20.16 "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader"
```

### Step 5: Compare running containers against expected (from Git)

```bash
# List stacks deployed via GitOps
ls ~/Documents/Claude/repos/homelab-gitops/stacks/

# Compare against running compose projects
ssh tmiller@192.168.20.15 "sudo docker compose ls --format 'table {{.Name}}\t{{.Status}}'"
```

## Expected Output

A health report listing:
- Total containers per host (running / stopped / unhealthy)
- Top resource consumers (CPU and memory)
- GPU utilization per card
- Any containers in unhealthy/restarting state
- Any drift between expected stacks (Git) and running stacks

## Failure Handling

- If SSH fails: report connectivity issue, hand off to Responder
- If unhealthy containers found: hand off to Responder with details
- If GPU OOM detected: hand off to Responder (likely vLLM restart needed)

## Report

Write to: `reports/YYYY-MM-DD-sentinel-health-check.md`
