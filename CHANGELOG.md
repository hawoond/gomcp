# Changelog

All notable changes are documented in this file.

## Unreleased

### Added

- Paginated tool, resource, template, and prompt discovery
- Resource subscriptions, scoped update notifications, and SSE event replay
- Completion handlers and client-side elicitation handlers
- Concurrent stdio request multiplexing and cancellation notifications
- Generated output schemas with typed tool output validation
- Bearer-token verification, token sources, and protected-resource metadata
- Stateful session retention controls and stateless HTTP mode
- Optional command and HTTP executor package
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

- HTTP notification queues and task ownership are isolated by session
- Dynamic protocol extensions use the `x-gomcp/` namespace
- Dynamic execution is separated from the core server protocol layer
- Default protocol preference is `2025-11-25`
- Unsupported client versions negotiate to the server preference
- Dynamic command and HTTP definitions require local allowlists
- Protocol-level mutation methods are disabled by default
- Tool calls and resource reads use MCP result envelopes

### Fixed

- Concurrent stdio calls no longer block behind an unrelated request
- Reconnecting HTTP clients can resume bounded notification history
- Resource templates no longer appear in the fixed-resource list
- Dynamic unregister operations no longer delete static registrations
- Numeric reflection conversion preserves the requested integer type
- Multiple resource-template variables are supported
- Handler panics are converted to protocol errors
- Async tasks no longer remain in memory indefinitely
- HTTP and process resources are closed and reaped consistently

### Security

- Bearer tokens support expiry and required-scope validation
- Task lookup, results, cancellation, and notifications are session-scoped
- Remote dynamic execution is disabled by default
- Outbound HTTP definitions reject non-public targets and redirects
- Request and response bodies are bounded
- API-key comparison uses constant-time comparison
