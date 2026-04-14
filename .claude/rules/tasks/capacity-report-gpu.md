---
description: Task — Analyze GPU utilization and forecast capacity needs
globs:
  - "**/*"
---

# Task: GPU Capacity Report

**Agent**: Planner
**Trigger**: On-demand, monthly, or when model changes are being considered
**Risk Level**: AUTO (read-only analysis)

## Procedure

### Step 1: Current GPU allocation

```bash
ssh tmiller@192.168.20.15 "nvidia-smi --query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu --format=csv"
ssh tmiller@192.168.20.16 "nvidia-smi --query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu --format=csv"
```

### Step 2: Map GPU assignments to models

Cross-reference with CLAUDE.md GPU Inventory table and running vLLM instances:
```bash
ssh tmiller@192.168.20.15 "sudo docker ps --filter name=vllm --format '{{.Names}}: {{.Image}}'"
ssh tmiller@192.168.20.16 "sudo docker ps --filter name=vllm --format '{{.Names}}: {{.Image}}'"
```

### Step 3: Analyze VRAM headroom

For each GPU: total VRAM - model VRAM = available headroom.
Flag any GPU above 90% VRAM utilization.

### Step 4: Forecast based on model trends

Consider: model size growth, new model candidates, concurrent user load.

## Report

Write to: `reports/YYYY-MM-DD-planner-capacity-forecast.md`
