# Contributing

## Development setup

Use a supported patched Go toolchain.

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
```

Run the vulnerability scan before proposing dependency or release changes:

```bash
govulncheck ./...
```

## Pull requests

- Keep protocol changes aligned with a named MCP specification version.
- Add tests for success, malformed input, cancellation, and concurrency paths.
- Preserve compatibility aliases when a safe migration path is possible.
- Document public API and behavior changes in `README.md` and `CHANGELOG.md`.
- Do not expose command execution or outbound HTTP without explicit allowlists.

## Commit style

Use concise imperative commit subjects. Keep unrelated formatting and dependency
changes in separate commits when practical.
