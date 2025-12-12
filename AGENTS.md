# Enterprise Contract CLI - Agent Instructions

## Project Overview

The `ec` (Enterprise Contract) CLI is a command-line tool for verifying artifacts and evaluating software supply chain policies. It validates container image signatures, provenance, and enforces policies across various types of software artifacts using Open Policy Agent (OPA)/Rego rules.

## Essential Commands

### Building
```bash
make build          # Build ec binary for current platform (creates dist/ec)
make dist           # Build for all supported architectures
make clean          # Remove build artifacts
DEBUG_BUILD=1 make build  # Build with debugging symbols for gdb/dlv
make debug-run      # Run binary with delve debugger (requires debug build)
```

### Testing
```bash
make test           # Run all tests (unit, integration, generative)
make acceptance     # Run acceptance tests (Cucumber/Gherkin, 20m timeout)
make scenario_<name>  # Run single acceptance scenario (replace spaces with underscores)
make feature_<name>   # Run all scenarios in a single feature file

# Running specific tests
go test -tags=unit ./internal/evaluator -run TestSpecificFunction
cd acceptance && go test -test.run 'TestFeatures/scenario_name'
```

### Code Quality
```bash
make lint           # Run all linters (golangci-lint, addlicense, tekton-lint)
make lint-fix       # Auto-fix linting issues
make ci             # Run full CI suite (test + lint-fix + acceptance)
```

## Architecture

### Command Structure
Main commands in `cmd/`:
- **validate** - Validate container images, attestations, and policies
- **test** - Test policies against data (similar to conftest)
- **fetch** - Download and inspect attestations
- **inspect** - Examine policy bundles and data
- **track** - Track compliance status
- **sigstore** - Sigstore-related operations
- **initialize** - Initialize policy configurations

### Core Components

#### Policy Evaluation (`internal/evaluator/`)
- **Conftest Evaluator**: Main evaluation engine using OPA/Rego
- **Pluggable Rule Filtering**: Extensible system for filtering which rules run based on:
  - Pipeline intentions (build vs release vs production)
  - Include/exclude lists (collections, packages, specific rules)
  - Custom metadata criteria
- **Result Processing**: Complex rule result filtering with scoring, severity promotion/demotion, and effective time handling

**Key Implementation Details:**
- PolicyResolver interface provides comprehensive policy resolution for pre and post-evaluation filtering
- UnifiedPostEvaluationFilter implements unified filtering logic
- Sophisticated scoring system for include/exclude decisions (collections: 10pts, packages: 10pts per level, rules: +100pts, terms: +100pts)
- Term-based filtering allows fine-grained control (e.g., `tasks.required_untrusted_task_found:clamav-scan`)
- See `.cursor/rules/rule_filtering_process.mdc` and `.cursor/rules/package_filtering_process.mdc` for detailed documentation

#### Attestation Handling (`internal/attestation/`)
- Parsing and validation of in-toto attestations
- SLSA provenance processing (supports both v0.2 and v1.0)
- Integration with Sigstore for signature verification

#### VSA (Verification Summary Attestation) (`internal/validate/vsa/`)
VSA creates cryptographically signed attestations containing validation metadata and policy information after successful image validation.

**Layered Architecture:**
1. Core Interfaces (`interfaces.go`) - Fundamental VSA interfaces
2. Service Layer (`service.go`) - High-level VSA processing orchestration
3. Core Logic (`vsa.go`) - VSA data structures and predicate generation
4. Attestation (`attest.go`) - DSSE envelope creation and signing
5. Storage (`storage*.go`) - Abstract storage backends (local, Rekor)
6. Retrieval (`*_retriever.go`) - VSA retrieval mechanisms
7. Orchestration (`orchestrator.go`) - Complex VSA processing workflows
8. Validation (`validator.go`) - VSA validation with policy comparison
9. Command Interface (`cmd/validate/vsa.go`) - CLI for VSA validation

**Key Features:**
- Policy comparison and equivalence checking
- DSSE envelope signature verification (enabled by default)
- Multiple storage backends (local filesystem, Rekor transparency log)
- VSA expiration checking with configurable thresholds
- Batch validation from application snapshots with parallel processing

See `.cursor/rules/vsa_functionality.mdc` for comprehensive documentation.

#### Input Processing (`internal/input/`)
- Multiple input sources: container images, files, Kubernetes resources
- Automatic detection and parsing of different artifact types

#### Policy Management (`internal/policy/`)
- OCI-based policy bundle loading
- Git repository policy fetching
- Policy metadata extraction and rule discovery

### Key Internal Packages
- `internal/signature/` - Container image signature verification
- `internal/image/` - Container image operations and metadata
- `internal/kubernetes/` - Kubernetes resource processing
- `internal/utils/` - Common utilities and helpers
- `internal/rego/` - Rego policy compilation and execution
- `internal/format/` - Output formatting (JSON, YAML, etc.)

## Module Structure

The project uses multiple Go modules:
- **Root module** - Main CLI application
- **acceptance/** - Acceptance test module with Cucumber integration
- **tools/** - Development tools and utilities

## Testing Strategy

### Test Types
- **Unit tests** (`-tags=unit`, 10s timeout) - Fast isolated tests
- **Integration tests** (`-tags=integration`, 15s timeout) - Component integration
- **Generative tests** (`-tags=generative`, 30s timeout) - Property-based testing
- **Acceptance tests** (20m timeout) - End-to-end Cucumber scenarios with real artifacts
  - Use `-persist` flag to keep test environment after execution for debugging
  - Use `-restore` to run tests against persisted environment
  - Use `-tags=@focus` to run specific scenarios

### Acceptance Test Framework
- Uses Cucumber/Gherkin syntax for feature definitions in `features/` directory
- Steps implemented in Go using Godog framework
- Self-contained test environment using Testcontainers
- WireMock for stubbing HTTP APIs (Kubernetes apiserver, Rekor)
- Snapshots stored in `features/__snapshots__/` (update with `UPDATE_SNAPS=true`)

## Development Environment

### Required Tools
- Go 1.24.4+
- Make
- Podman/Docker for container operations
- Node.js for tekton-lint

### Troubleshooting Common Issues

1. **Go checksum mismatch**
   ```bash
   go env -w GOPROXY='https://proxy.golang.org,direct'
   ```

2. **Container failures** - Ensure podman runs as user service, not system service
   ```bash
   systemctl status podman.socket podman.service
   systemctl disable --now podman.socket podman.service
   systemctl enable --user --now podman.socket podman.service
   ```

3. **Too many containers** - Increase inotify watches
   ```bash
   echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
   ```

4. **Key limits** - Increase max keys
   ```bash
   echo kernel.keys.maxkeys=1000 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
   ```

5. **Host resolution** - Add to `/etc/hosts`:
   ```
   127.0.0.1 apiserver.localhost
   127.0.0.1 rekor.localhost
   ```

## Key Configuration

### Policy Sources
Policies can be loaded from:
- OCI registries: `oci::quay.io/repo/policy:tag`
- Git repositories: `git::https://github.com/repo//path`
- Local files/directories

### Debug Mode
- Use `--debug` flag or `EC_DEBUG=1` environment variable
- Debug mode preserves temporary `ec-work-*` directories for inspection

## Special Considerations

### CGO and DNS Resolution
Binaries are built with `CGO_ENABLED=0` for OS compatibility, which affects DNS resolution. The Go native resolver cannot resolve second-level localhost domains like `apiserver.localhost`, requiring manual `/etc/hosts` entries for acceptance tests.

### Multi-Architecture Support
The build system supports all major platforms and architectures. Use `make dist` to build for all supported targets or `make dist/ec_<os>_<arch>` for specific platforms.

### Policy Rule Filtering System
The evaluation system includes sophisticated rule filtering that operates at multiple levels:

#### Pre-Evaluation Filtering (Package Level)
1. **Pipeline Intention Filtering** (ECPolicyResolver only)
   - When `pipeline_intention` is set: only include packages with matching metadata
   - When not set: only include general-purpose rules (no pipeline_intention metadata)

2. **Rule-by-Rule Evaluation**
   - Each rule is scored against include/exclude criteria
   - Scoring system: collections (10pts), packages (10pts/level), rules (+100pts), terms (+100pts)
   - Higher score determines inclusion/exclusion

3. **Package-Level Determination**
   - If ANY rule in package is included → Package is included
   - Package runs through conftest evaluation

#### Post-Evaluation Filtering (Result Level)
- UnifiedPostEvaluationFilter processes all results using same PolicyResolver
- Filters warnings, failures, exceptions, skipped results
- Applies severity logic (promotion/demotion based on metadata)
- Handles effective time filtering (future-effective failures → warnings)

#### Term-Based Filtering
Terms provide fine-grained control over specific rule instances:
- Example: `tasks.required_untrusted_task_found:clamav-scan` (scores 210pts)
- Can override general patterns like `tasks.*` (10pts)
- Terms are extracted from result metadata during filtering

### Working with Rule Filtering Code
When modifying policy evaluation or filtering logic:
1. Read `.cursor/rules/package_filtering_process.mdc` for architecture overview
2. Read `.cursor/rules/rule_filtering_process.mdc` for detailed filtering flow
3. Main filtering code is in `internal/evaluator/filters.go`
4. Integration point is in `internal/evaluator/conftest_evaluator.go`

### Working with VSA Code
When modifying VSA functionality:
1. Read `.cursor/rules/vsa_functionality.mdc` for complete documentation
2. Understand the layered architecture (9 layers from interfaces to CLI)
3. VSA code is in `internal/validate/vsa/` directory
4. CLI implementation in `cmd/validate/vsa.go`
5. Signature verification is enabled by default and implemented via DSSE envelopes

## Additional Documentation

For detailed implementation guides, see:
- `.cursor/rules/package_filtering_process.mdc` - Pluggable rule filtering system
- `.cursor/rules/rule_filtering_process.mdc` - Complete rule filtering process
- `.cursor/rules/vsa_functionality.mdc` - VSA architecture and workflows
