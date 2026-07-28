# Changelog

All notable changes are documented in this file.

## Unreleased

### Added

- Streamable HTTP sessions with protocol-version headers
- Standard tool, resource, prompt, and task result types
- Typed tool registration and generated JSON Schema
- Task listing, cancellation, result retrieval, TTL, and capacity controls
- Request, response, command, and outbound HTTP limits
- Origin validation, graceful shutdown, and public HTTP handler
- Client context APIs, concurrent HTTP calls, and session cleanup
- Race, transport, lifecycle, schema, panic, task, and URI-template tests
- CI, security policy, contribution guide, and runnable examples

### Changed

- Default protocol preference is `2025-11-25`
- Unsupported client versions negotiate to the server preference
- Dynamic command and HTTP definitions require local allowlists
- Protocol-level mutation methods are disabled by default
- Tool calls and resource reads use MCP result envelopes

### Fixed

- Dynamic unregister operations no longer delete static registrations
- Numeric reflection conversion preserves the requested integer type
- Multiple resource-template variables are supported
- Handler panics are converted to protocol errors
- Async tasks no longer remain in memory indefinitely
- HTTP and process resources are closed and reaped consistently

### Security

- Remote dynamic execution is disabled by default
- Outbound HTTP definitions reject non-public targets and redirects
- Request and response bodies are bounded
- API-key comparison uses constant-time comparison
