---
description: File hygiene and self-organizing rules for workspace tidiness
globs:
  - "**/*"
---

# File Hygiene Rules

These rules keep workspaces tidy. They are enforced by Claude at session
start and end, and during file creation.

## Workspace Root Rule

Nothing lives at a workspace root except `CLAUDE.md` and `.claude/`.

All other files MUST go in one of these directories:
- `reports/` — operational reports, audit outputs, runbooks
- `projects/<name>/` — project artifacts (design docs, scripts, configs)
- `scratch/` — temporary working files (auto-flagged if >7 days old)
- `drafts/` — blog drafts (content workspace only)

**Claude REFUSES to create files outside these directories within a workspace.**
If unsure where a file belongs, ask Todd.

## Project File Rule

Within a project directory, files live at the project root or in `reports/`.
No other subdirectories unless the project specifically needs them (e.g., a
`scripts/` dir for a complex implementation). Keep it flat.

## Scratch Lifecycle

- Scratch files are for temporary working data (test outputs, debug dumps, etc.)
- Every scratch file MUST have its purpose noted in the first line
- Files in `scratch/` older than 7 days MUST be flagged for cleanup at session start
- Claude MUST propose: keep (with reason), archive, or delete

## Session & Lifecycle

Session start/end protocols and project lifecycle states are defined in
`governance.md` (the canonical source). File-hygiene-specific checks during sessions:

- **Session start**: MUST check for files at workspace root that don't belong;
  MUST check `scratch/` for files older than 7 days; MUST check for completed-but-not-archived projects.
- **Session end**: MUST propose cleanup actions if any are pending.

## Single Source of Truth

Every concept, rule, or data point MUST have exactly ONE canonical location.
Before writing new content to a rules file, MUST check whether the concept is already
covered elsewhere. New files MUST cross-reference existing rules, not duplicate
them. If content exists in two places it WILL drift apart.

Canonical locations:
- **Session protocol**: `governance.md`
- **Risk framework**: `governance.md`
- **Agent definitions**: `.claude/rules/agents/`
- **Task procedures**: `.claude/rules/tasks/` (auto-load) and `task-library/` (reference)
- **File placement rules**: this file (`file-hygiene.md`)
- **Workspace boundaries**: `workspaces/<ws>/.claude/rules/scope.md`
- **Infrastructure reference**: global `CLAUDE.md`
- **Domain knowledge**: `workspaces/<ws>/CLAUDE.md`
- **Credential lifecycle**: `governance.md` (rules) + `task-library/secret-rotate.md` (procedure + inventory)

## Git Repository (claude-workspaces)

This directory is a git repo: `https://github.com/tmttodd/claude-workspaces` (private)

**Before any commit, Claude MUST follow this checklist:**

1. **Secret scan**: Run `git diff --cached` and grep for patterns that indicate
   secrets: API keys, tokens, passwords, connection strings, `.env` contents.
   Specific patterns to catch:
   - `sk-`, `ghp_`, `hlab-`, `op://`, `eyJ` (JWT), `tvly-`
   - Any string that looks like `KEY=value` with a high-entropy value
   - Files named `*.env*`, `*secret*`, `*credential*`, `*token*`
   If found: unstage the file, add to `.gitignore`, report to Todd.

2. **Size check**: Run `git status` and check for unexpectedly large files or
   directories. Anything over 10MB should be questioned. The `reference/` and
   `archive/` directories may contain large data — verify `.gitignore` excludes them.

3. **Embedded repo check**: Look for warnings about "embedded git repository"
   during `git add`. These must be excluded via `.gitignore`, not committed.

4. **Authentication**: GitHub credentials are in the macOS keychain (used
   automatically by `git push` via HTTPS). Do NOT hardcode PATs in commands.
   For GitHub API calls, retrieve the PAT from keychain:
   ```
   security find-internet-password -s github.com -w
   ```
   If the keychain entry is ever recreated, **ALWAYS use `-A`**:
   ```
   security add-internet-password -s github.com -a oauth2 -w "<token>" -r htps -A
   ```
   Without `-A`, macOS prompts for login password on every `git push`.

5. **Commit message**: Follow standard format with Co-Authored-By trailer.

**What is NOT in git** (managed by `.gitignore`):
- `repos/` and `ansible/` (separate git repositories)
- `reference/vojvodina/`, `reference/genealogy/` (large data files)
- `archive/ai-stack-portal/` (large artifacts)
- `**/scratch/*` (ephemeral by design)
- Any file containing secrets (explicit entries in `.gitignore`)
- `.mcp.json`, `.claude/settings.local.json` (local config)

## Global Root Rule

The global `~/Documents/Claude/` root should contain only:
- `CLAUDE.md`, `.mcp.json`, `.claude/`
- `workspaces/`, `repos/`, `ansible/`, `task-library/`
- `reference/`, `assets/`, `archive/`

Nothing else. No loose scripts, docs, or artifacts. If it doesn't fit in
one of these locations, it MUST NOT be placed at the root.
