# Task: Knowledge-Augmented Retrieval

**When**: Before reading a file to answer a question about past work, procedures,
infrastructure state, or operational knowledge.

**Why**: Searching the knowledge base returns targeted chunks (~200-500 tokens)
instead of loading entire files (~2000-5000 tokens). This preserves context
window for actual work.

## When to Search First

Before reading a file to answer a question about:
- Past incidents or how something was previously fixed
- Procedures, runbooks, or "how do I do X?"
- Infrastructure state, dependencies, or topology
- Why something is configured a certain way
- Standards, policies, or governance rationale
- What services depend on a given service
- Troubleshooting patterns for a specific technology

Use:
```
mcp__litellm-mcp__admin_api-search_knowledge(query="...", limit=5)
```

Optional filters:
- `doc_type`: runbook, procedure, incident, config, architecture, debugging, decision, standard, cmdb, dependency
- `workspace`: ai, core, automation, media, homeauto, monitoring, security, content

## When to Read the File Instead

- The file is already loaded in context (rules files, CLAUDE.md)
- You need the ENTIRE file content, not just a relevant section
- You need to EDIT the file (search gives you chunks, not the full file)
- The knowledge base returns no results or low-confidence results
- You're looking at code that needs exact line numbers

## When to Ingest

At session end, ingest notable learnings:
```
mcp__litellm-mcp__admin_api-ingest_knowledge(
  text="[the learning]",
  source="session",
  doc_type="insight|debugging|decision|pattern",
  metadata={"workspace": "...", "project": "...", "date": "YYYY-MM-DD", "agent": "..."}
)
```

Ingest when you discover:
- A non-obvious debugging solution
- An undocumented behavior
- A decision and its rationale
- A workaround that future sessions should know
- A pattern that applies across multiple situations

Do NOT ingest:
- Information already in Git-tracked files (it will be indexed on merge)
- Secrets, credentials, or high-entropy strings
- Temporary observations that won't matter in a week
