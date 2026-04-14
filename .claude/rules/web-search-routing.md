# Web Search Routing

The built-in `WebSearch` tool requires Anthropic's backend and returns 0 results
when running with local models via LiteLLM. **NEVER use the built-in `WebSearch`
tool.** It will silently fail.

## How to search the web

Use the SearXNG MCP tools via the `litellm-mcp` server:

| Task | Tool |
|------|------|
| Web search | `mcp__litellm-mcp__searxng-search` |
| Search suggestions | `mcp__litellm-mcp__searxng-get_suggestions` |
| List search engines | `mcp__litellm-mcp__searxng-list_engines` |

### Usage

```
mcp__litellm-mcp__searxng-search:
  query: "your search terms"
  categories: "general"        # optional: general, images, news, science, files, it
  engines: "google,duckduckgo"  # optional: specific engines
  language: "en"                # optional
  max_results: 10               # optional
```

## Why

SearXNG is self-hosted at `https://search.themillertribe-int.org` and proxied
through LiteLLM's MCP endpoint. It works with both Anthropic-hosted and local
model sessions. The built-in `WebSearch` only works when connected directly to
Anthropic's API.
