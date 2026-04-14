# Local Model File Editing

When using local models (non-Anthropic, via LiteLLM), prefer these MCP tools
over the built-in Edit tool for better accuracy:

| Task | Use This Tool | Instead Of |
|------|--------------|------------|
| Replace a line | `file_edit` (line number + new content) | Edit (exact string match) |
| Replace multiple lines | `file_replace_block` (line range + new content) | Edit (exact string match) |
| Insert new lines | `file_insert` (after line N) | Edit (find insertion point) |
| Delete lines | `file_delete` (line range) | Edit (replace with empty) |
| Edit YAML by path | `yaml_edit` (dot notation path) | Edit (exact string match) |

**Workflow:**
1. Use `Read` or `file_read` to see line numbers
2. Use `file_edit`, `file_replace_block`, `file_insert`, or `file_delete` by line number
3. If making multiple edits to the same file, work from bottom to top (highest line numbers first)

The `file_edit` tool supports an optional `expected_content` parameter that
verifies the line contains what you expect before editing. Use this when making
sequential edits to catch stale line numbers.
