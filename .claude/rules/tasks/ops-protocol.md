# Task: Operational Protocol — Unified Agent Coordination

**When**: Every CC session that involves infrastructure state changes.

**Why**: CC and NemoClaw share infrastructure. Without a unified protocol, actions
taken by one agent are invisible to the other. This protocol ensures both agents
follow the same operational discipline.

## Pre-Action Conflict Check (MANDATORY)

Before ANY MODIFY+ action on an infrastructure target (container restart, config
change, deployment, secret rotation), CC MUST:

```
corvus_check_target(target="<container_or_service_name>")
```

Fallback if Corvus MCP tools unavailable: `ops_check_target(target="...")`

Interpret the result:
- **GO**: No conflicts. Proceed normally.
- **CAUTION**: Recent activity on this target. Review the detail before proceeding.
  State what you saw and why you're proceeding anyway.
- **STOP**: Active change window or recent incident. Do NOT act without asking Todd.

## Blast Radius Check (RECOMMENDED)

Before restarting or modifying a service, check what depends on it:

```
corvus_blast_radius(service="<service_name>")
```

If `affected_count > 0`, state the downstream services in the risk assessment.
This turns "restarting caddy" into "restarting caddy, which affects N services."

## Dependency Chain Check (RECOMMENDED)

When investigating a failure, check what the service depends on:

```
corvus_dependency_chain(service="<service_name>")
```

If an upstream dependency is unhealthy, fix that first.

## Event Emission (MANDATORY)

CC MUST emit events for all state-changing actions via `corvus_emit_event`
(fallback: `ops_emit_event`):

| CC Action | Event Type | Source |
|-----------|-----------|--------|
| Responder restarts container | `remediation.restart` | `claude-code` |
| Responder investigates issue | `incident.investigating` | `claude-code` |
| Responder resolves issue | `incident.resolved` | `claude-code` |
| Changemaker merges PR | `change.completed` | `claude-code` |
| Changemaker creates change window | `change.started` | `claude-code` |
| Sentinel detects anomaly | `sweep.anomaly` | `claude-code` |
| Any APPROVE action executed | `action.approved` | `claude-code` |

## Incident Records (MANDATORY)

When CC's Responder handles an infrastructure issue, MUST create a SOP incident:

```
corvus_create_incident(
    target="<container_name>",
    title="<short title>",
    description="<what happened>",
    severity="warning|critical",
    detected_by="claude-code"
)
```

Fallback: `ops_create_incident(...)` via admin-api.

The markdown incident report in `reports/` is STILL written (for detail), but the
SOP record is the canonical tracking mechanism visible to both agents.

## Event Feed Check (RECOMMENDED)

At natural breakpoints, check what NemoClaw has been doing:

```
corvus_watch_events(since="<ISO8601>", severity="warning")
```

Fallback: `ops_watch_events(min_severity="warning")`

Natural breakpoints:
- Before any MODIFY+ action (covered by conflict check above)
- After completing each Standard Workflow phase
- When switching agent roles
- Before presenting CHECKPOINT to Todd

## Session End Verification

At session end, verify:
1. All state-changing actions emitted events
2. Any incidents created during session have SOP records
3. Any change windows opened during session are closed

## Shared Event Type Taxonomy

Both CC and NemoClaw use these event types:

```
change.started / change.completed / change.failed
incident.opened / incident.investigating / incident.resolved / incident.escalated
remediation.restart / remediation.config_fix / remediation.credential_rotation
session.started / session.ended
action.approved / action.denied / action.escalated
sweep.completed / sweep.anomaly
```

New event types require documentation before use.
