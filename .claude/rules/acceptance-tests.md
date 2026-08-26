---
paths:
  - "acceptance/**"
---

# Acceptance Test Rules

- Tests use Cucumber/Gherkin via Godog with Testcontainers for infrastructure
- Run single scenario: `make scenario_<name>` (replace spaces with underscores)
- Use `-persist` flag to keep test env for debugging, `-restore` to rerun
- Snapshot testing: update with `UPDATE_SNAPS=true make acceptance`
- macOS requires Podman machine — see `hack/macos/README.md`
- When writing acceptance tests that supply a parameter to a task, use a value
  distinct from the task's default to verify the parameter is actually propagated
  (not just falling through to the default)
