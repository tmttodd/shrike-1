---
description: Development governance — auto-enforces quality gates for all software work
globs:
  - "**/*"
---

# Development Governance

Auto-enforced quality gates for software development. Todd does NOT need to invoke
anything — Claude classifies requests and follows the correct workflow automatically.

This framework is ADDITIVE to governance.md. It never weakens infrastructure rules.

## Request Classification (Software Development)

When Todd's request involves writing code, scripts, tools, or software artifacts,
classify and route automatically:

| Request Pattern | Scope | Starting Step |
|----------------|-------|---------------|
| "Build X", "Create X", "Make a tool" | Medium/Large | Step 0 (Project Gate) |
| "Add feature to Y", "Extend Y" | Small/Medium | Step 1 |
| "Fix bug in X", "X doesn't work" (code) | Trivial/Small | Step 1 → Step 4 |
| "Refactor X", "Clean up X" | Small | Step 4 (lock behavior with tests first) |
| "Update dependency X" | Trivial | Step 6 → Step 10 |
| "Write tests for X" | Trivial | Step 4 directly |
| "Script to do X" | Small | Step 1 |

## Scope Scaling

| Scope | Definition | Steps Applied |
|-------|-----------|---------------|
| **Trivial** | Single function, bug fix, config tweak | 4-5-7-10 |
| **Small** | New file, feature in existing project | 1-2-4-5-6-7-8-10-11 |
| **Medium** | Multi-file feature, new integration | All steps, verbal design |
| **Large** | New project, new system, multi-session | All steps, written reports |

When unsure, default to the next higher scope. Todd can override DOWN, but Claude
MUST state what gates are being skipped and why they normally matter.

## Development Workflow

```
Step 0:  PROJECT GATE — create project dir + CLAUDE.md (Large scope only)
Step 1:  UNDERSTAND — clarify requirements, research existing code
Step 2:  DESIGN — propose approach, threat model, acceptance criteria
         + LEAN REVIEW (self-applied: simplest solution? YAGNI? existing code?)
Step 3:  CHALLENGE — Advocate reviews design (Medium/Large scope only)
         ── CHECKPOINT: present design + challenge to Todd (Large only) ──
Step 4:  VERIFY FIRST — verification gate (see below)
Step 5:  IMPLEMENT — write code following coding-standards.md
Step 6:  SECURITY SCAN — dependencies, secrets, OWASP patterns
Step 7:  QUALITY CHECK — lint, format, complexity, DRY
Step 8:  SELF-REVIEW — adversarial checklist (see below)
Step 9:  DOCUMENTATION — docstrings, README, config docs
Step 10: FINAL VERIFICATION — full test suite, acceptance criteria confirmed
Step 11: DELIVER — commit, present summary, note friction in Decision Log
```

## Verification Gate (Step 4) — MANDATORY, Mechanism Varies

| Work Type | Verification Method |
|-----------|-------------------|
| Functions, APIs, libraries | **TDD**: Write failing tests BEFORE implementation |
| Shell scripts, config generators | **Verification plan**: Define what to check after implementation |
| Prototypes, exploratory code | **Post-implementation tests**: Tests MUST exist before "done" |
| Refactoring | **Behavior-locking tests**: Capture current behavior before changing |

The gate is always mandatory. You cannot ship without verified correctness.

## Security Shift-Left (Embedded at Every Step)

| Step | Security Check |
|------|---------------|
| Design | Threat model: auth gaps, data exposure, injection surfaces |
| Verify First | Security test cases: injection, auth bypass, data leakage |
| Implement | Coding standards enforce OWASP patterns |
| Security Scan | CVE audit, secret scan, known bad patterns |
| Self-Review | Adversarial checklist includes security items |

## Self-Review Adversarial Checklist (Step 8)

Claude MUST check each item — not subjectively "re-read":

- [ ] Off-by-one errors in loops, ranges, slices
- [ ] Unclosed resources (files, connections, locks, cursors)
- [ ] Race conditions in async/concurrent code
- [ ] Error messages that leak internal paths, stack traces, or secrets
- [ ] Hardcoded values that should be configurable
- [ ] Missing input validation at system boundaries (user input, API params, env vars)
- [ ] Exception handling: catching too broadly (`except Exception`) or swallowing errors
- [ ] SQL/command injection via string interpolation
- [ ] Secrets or credentials in code, logs, or error output
- [ ] Functions doing too much (>50 lines = split candidate)
- [ ] Missing edge cases: empty input, None/null, boundary values, unicode
- [ ] Return types consistent (don't return str sometimes, None other times)

## Dev → Infra Handoff

When development produces a deployable artifact (Docker container, Prefect flow,
Ansible playbook, CI config):
1. Development Workflow Steps 1-10 govern **code quality**
2. Infrastructure Standard Workflow Steps 1-11 govern **deployment**
3. Dev Step 11 (Deliver) TRIGGERS Infra Standard Workflow
4. Neither workflow substitutes for the other

## Anti-Bypass Rules

| Anti-Pattern | Enforcement |
|-------------|-------------|
| "Tests aren't needed for this" | Verification gate is ALWAYS mandatory. Mechanism varies, gate doesn't. |
| "I'll add tests later" | Implementation (Step 5) CANNOT begin without Step 4 complete. |
| "Security scan is overkill" | Security scan (Step 6) is mandatory for ALL code. No exceptions. |
| "The code is self-documenting" | Documentation gate (Step 9) requires explicit artifacts. |
| "Quick fix, skip ceremony" | Trivial scope still requires 4 gates. No work has zero gates. |
| "Todd said skip it" | Record the override in Decision Log. Overrides don't set precedent. |
| Implementing before designing | Step 5 checks: does a design (Step 2) exist? If no → STOP. |

## Session Continuity

At any gate boundary, update project CLAUDE.md "Current State" with the last
completed gate and what comes next. If a session ends mid-workflow, the next
session resumes at the last completed gate. If a security scan finds critical
issues, STOP and present to Todd (mirrors the deployment failure hard gate).

## Feedback Loop

After each software delivery, note in the project Decision Log:
- Which gates added value
- Which gates created unnecessary friction
- After 5 projects: review notes and calibrate scope thresholds
