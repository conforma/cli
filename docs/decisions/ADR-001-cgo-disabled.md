# ADR-001: CGO Disabled for Portability

## Status

Accepted

## Context

The ec binary needs to run across multiple platforms and architectures. CGO introduces dependencies on system libraries that vary across platforms, making cross-compilation difficult and potentially causing runtime issues.

Additionally, CGO affects DNS resolution behavior. The Go native resolver cannot resolve second-level localhost domains like `apiserver.localhost`, which is relevant for acceptance tests.

## Decision

Build ec binaries with `CGO_ENABLED=0`.

This means:
- Using Go's native DNS resolver instead of the system libc resolver
- No dependencies on platform-specific C libraries
- Simplified cross-compilation

## Consequences

### Positive
- Single binary works across all supported platforms
- Simplified build process
- No C compiler required for builds
- Reproducible builds

### Negative
- Cannot use C libraries directly
- Go native DNS resolver has limitations (e.g., no mDNS, limited localhost subdomain resolution)
- Acceptance tests require manual `/etc/hosts` entries for `apiserver.localhost` and `rekor.localhost`

### Mitigations
- Document required `/etc/hosts` entries in README and AGENTS.md
- Use standard DNS where possible
