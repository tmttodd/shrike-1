---
description: Task — Create a feature branch and merge request in homelab-gitops
globs:
  - "**/*"
---

# Task: Git Branch and Merge Request

**Agent**: Changemaker
**Trigger**: When an infrastructure change is approved and ready to implement
**Risk Level**: AUTO (branch+edit+MR), APPROVE (merge)
**Estimated Duration**: 5-15 minutes

## Prerequisites

- Change has been designed (Architect) and challenged (Advocate)
- Todd has approved the design (or change is within AUTO scope)
- Up-to-date clone of homelab-gitops
- See `CLAUDE.md` Authority & Access section for GitOps path guidance

## Procedure

### Step 1: Ensure repo is on main and up to date

```bash
cd ~/Documents/Claude/repos/homelab-gitops
git checkout main
git pull origin main
```

### Step 2: Create feature branch

```bash
# Branch naming: feature/<project-number>-<brief-description>
git checkout -b feature/<NN>-<description>
```

### Step 3: Make changes

Edit the relevant files. Always include in the commit message:
- Project number and name
- What changed and why
- Risk level from governance framework

### Step 4: Commit and push

```bash
git add <specific-files>
git commit -m "feat(project-NN): <description>

<detailed explanation>

Risk: <blast-radius> / <reversibility> / <autonomy-level>"

git push -u origin feature/<NN>-<description>
```

### Step 5: Create merge request

Use GitLab API or web UI. MR description must include:
- **Summary**: What this MR does
- **Risk Assessment**: Blast radius, reversibility, autonomy level
- **Affected Services**: Which containers/stacks/hosts
- **Rollback Plan**: How to undo if something breaks
- **Testing**: How to verify the change works

### Step 6: Wait for Todd's approval

Do NOT merge. Notify Todd the MR is ready for review.

## Failure Handling

- If branch has conflicts: rebase on main, resolve, force-push branch (NEVER force-push main)
- If CI/CD fails: fix in the branch, push again
- If Todd rejects: discuss, revise, or close MR

## Report

Write MR description to: `reports/YYYY-MM-DD-changemaker-mr-description.md`
