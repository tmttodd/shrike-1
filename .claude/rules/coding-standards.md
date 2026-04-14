---
description: Coding standards for all software development — universal principles
globs:
  - "**/*"
---

# Coding Standards

Universal principles for all code written in this environment. These are DEFAULTS —
if a project CLAUDE.md or existing codebase defines its own conventions (style guide,
linting config, naming patterns), project conventions take precedence. These standards
apply only where the project is silent.

For language-specific details, see `task-library/coding-standards-<lang>.md`.

## Naming & Structure

- Names describe WHAT something is or DOES, not HOW it works
- Functions do ONE thing. If the name needs "and," split the function
- Files organize by feature/domain, not by type (avoid `utils/`, `helpers/`)
- Constants are UPPER_SNAKE_CASE. Variables and functions use the language convention
- Boolean names read as questions: `is_valid`, `has_permission`, `can_retry`
- Abbreviations only if universally understood (`url`, `id`, `http`). Never `mgr`, `impl`, `cfg`
- Maximum function length: 50 lines. Beyond that, extract sub-functions
- Maximum function parameters: 5. Beyond that, use a config/options object

## Error Handling

- Catch SPECIFIC exceptions, never bare `except:` or `catch (Exception e)`
- Every caught exception must be: logged, re-raised, or explicitly justified if swallowed
- Error messages include: WHAT failed, WHY (if known), and HOW to fix (if actionable)
- Never expose internal paths, stack traces, or secrets in user-facing errors
- Fail FAST at system boundaries (invalid input → immediate error, not silent default)
- Return types are CONSISTENT: a function that returns a list never returns None
- Use early returns to reduce nesting. Guard clauses at the top, happy path below

## Security (OWASP-Aligned)

- NEVER construct SQL, shell commands, or HTML via string concatenation/interpolation
- Use parameterized queries, subprocess lists, and template engines respectively
- NEVER hardcode secrets, credentials, API keys, or connection strings in code
- All secrets come from environment variables, config files (gitignored), or secret managers
- Validate ALL external input at system boundaries: user input, API params, env vars, file content
- Sanitize output that enters different contexts (HTML, SQL, shell, log entries)
- Use HTTPS for all external requests. Verify TLS certificates (never `verify=False` in production)
- Log security-relevant events (auth attempts, permission changes, data access)
- Never log secrets, tokens, passwords, or full request bodies containing auth data
- File operations: validate paths, prevent traversal (`../`), use allowlists for extensions
- Authentication: use established libraries, never roll custom auth/crypto

## Logging & Observability

- Log at appropriate levels: ERROR (broken), WARNING (degraded), INFO (events), DEBUG (details)
- Every log entry must have: timestamp (automatic), message, and relevant context (IDs, counts)
- Structured logging preferred (key=value or JSON) over unstructured strings
- Never log at ERROR for expected conditions (e.g., user input validation failures = WARNING)
- Include correlation IDs for request tracing across services

## Configuration

- All configuration is external to code (env vars, config files, CLI args)
- Every config value has a sensible DEFAULT or fails fast with a clear error if required
- Config is validated at startup, not at first use (fail fast)
- Configuration hierarchy: CLI args > env vars > config file > defaults
- Document every config option: name, type, default, description, example

## Dependencies

- Pin EXACT versions in production lockfiles (no floating `^` or `~`)
- Every new dependency must justify its existence: what does it save vs. the risk it adds?
- Prefer standard library over third-party when the standard library solution is reasonable
- Check license compatibility before adding (avoid GPL in proprietary, AGPL in services)
- Audit for known CVEs before adding: `pip audit`, `npm audit`, `cargo audit`
- One dependency per concern. Avoid mega-frameworks when focused libraries exist

## Documentation

- Code-level: docstrings/comments explain WHY, not WHAT (code shows what)
- Public functions/classes: docstring with purpose, params, return, raises
- Module-level: brief description of what this file/module is responsible for
- README (if user-facing): purpose, installation, usage example, configuration, troubleshooting
- API docs: endpoint, method, params, request/response examples, error codes
- Comment TODOs include: what, why, and who should do it (`# TODO(name): reason`)
- Remove dead code. Don't comment it out "just in case" — that's what git is for

## Testing

- Tests are not optional. See `dev-governance.md` Verification Gate for when/how
- Test names describe the scenario: `test_login_fails_with_expired_token`
- Each test tests ONE behavior. Multiple assertions only if they verify one concept
- Tests are independent: no shared mutable state, no execution order dependency
- Test the PUBLIC interface, not internal implementation details
- Use fixtures/factories for test data, not hardcoded values scattered across tests
- Minimum coverage targets: critical paths 100%, overall 80%+
- Tests must be FAST. Slow tests get skipped and become useless

## Code Organization

- Imports at the top, grouped: stdlib → third-party → local (with blank lines between)
- No circular imports. If two modules need each other, extract shared code
- One concept per file. A 2000-line file is a package waiting to happen
- Keep related code close. If two functions always change together, they belong together
- Entry points are thin: parse args, configure, call business logic, handle errors
