# Security Policy

## Supported versions

Security fixes are applied to the latest released minor version. Older
pre-release versions may require upgrading before a fix can be applied.

## Reporting a vulnerability

Use GitHub's private security advisory flow for this repository when it is
available. If private reporting is unavailable, contact the maintainer through
the GitHub profile before publishing technical details.

Include:

- the affected version or commit
- a minimal reproduction
- the expected impact
- any known mitigations

Do not include credentials, tokens, private hostnames, or customer data.

## Deployment guidance

- Bind HTTP mode to loopback unless a trusted TLS reverse proxy is used.
- Enable authentication before exposing the endpoint beyond the local host.
- Keep protocol-level dynamic registration disabled.
- Allowlist every dynamic executable and outbound HTTP host.
- Do not allow dynamic HTTP targets that resolve to private, loopback,
  link-local, multicast, or unspecified addresses.
- Configure request, response, command, task, and client time limits.
- Build and test with a currently supported patched Go toolchain.
- Run `govulncheck ./...` before publishing a release.

## Security boundaries

Application tool, resource, and prompt handlers execute with the permissions of
the hosting process. The library validates transport and registration
boundaries, but handlers remain responsible for authorization, tenant
isolation, input-specific policy, and safe access to external systems.
