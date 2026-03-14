# Architecture Overview

## Module Structure

```
ec-cli/
├── cmd/               # Command implementations (CLI layer)
│   ├── validate/      # Validation commands
│   ├── fetch/         # Fetch commands
│   ├── inspect/       # Inspection commands
│   └── ...
├── internal/          # Private packages
│   ├── evaluator/     # Policy evaluation engine
│   ├── attestation/   # Attestation handling
│   ├── validate/      # Validation logic
│   │   └── vsa/       # VSA subsystem
│   ├── policy/        # Policy management
│   ├── image/         # Container image operations
│   ├── signature/     # Signature verification
│   ├── kubernetes/    # Kubernetes resource processing
│   ├── input/         # Input processing
│   ├── format/        # Output formatting
│   ├── rego/          # Rego compilation
│   └── utils/         # Common utilities
├── acceptance/        # Acceptance test module
├── features/          # Cucumber feature files
└── tools/             # Development tools
```

## Layer Dependencies

```
┌─────────────────────────────────────────┐
│                cmd/                     │  CLI Layer
├─────────────────────────────────────────┤
│    validate/    evaluator/   policy/    │  Business Logic
├─────────────────────────────────────────┤
│  attestation/   image/    signature/    │  Domain Services
├─────────────────────────────────────────┤
│        utils/       rego/       http/   │  Infrastructure
└─────────────────────────────────────────┘

Arrows point DOWN only. Higher layers may import lower layers.
Lower layers MUST NOT import higher layers.
```

## Key Subsystems

### Policy Evaluation (`internal/evaluator/`)

The core evaluation engine using OPA/Rego. Key components:
- **Conftest Evaluator**: Main evaluation engine
- **PolicyResolver**: Handles rule filtering (pre and post-evaluation)
- **UnifiedPostEvaluationFilter**: Result filtering and categorization

See [design-docs/rule-filtering.md](design-docs/rule-filtering.md) for details.

### VSA (`internal/validate/vsa/`)

Verification Summary Attestation handling. Layered architecture:
1. Core Interfaces
2. Service Layer
3. Core Logic
4. Attestation (DSSE)
5. Storage backends
6. Retrieval mechanisms
7. Validation

See [design-docs/vsa-architecture.md](design-docs/vsa-architecture.md) for details.

### Attestation (`internal/attestation/`)

Handles in-toto attestations and SLSA provenance (v0.2 and v1.0).

## Allowed Dependencies

| Package | May Import |
|---------|-----------|
| cmd/* | internal/* |
| internal/validate | internal/evaluator, internal/attestation, internal/policy |
| internal/evaluator | internal/rego, internal/policy |
| internal/attestation | internal/image, internal/signature |
| internal/utils | standard library only |

## Forbidden Dependencies

- `internal/*` MUST NOT import `cmd/*`
- `internal/utils` MUST NOT import other internal packages
- Circular dependencies are forbidden
