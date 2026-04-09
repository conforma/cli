# Tekton Task Bundle Validation POC

This directory contains a Rego policy for validating Tekton task bundles as OCI artifacts.

## Overview

This POC demonstrates running task policy checks against Tekton task bundles via `ec validate image`. The policy detects task bundles, extracts task definitions from bundle layers, and validates them -- all in Rego using existing `ec.oci.*` built-ins, with no Go code changes.

## Architecture

Everything lives in a single file: `task_bundle.rego` (package `task_bundle`).

### Detection
Checks OCI manifest layers for `dev.tekton.image.*` annotations to identify task bundles.

### Extraction
Iterates layers where `dev.tekton.image.kind == "task"`, builds blob references (`repo@digest`), and uses `ec.oci.blob_files()` to pull task definitions from each layer's tar archive. Results are collected in `_task_definitions`.

### Validation Rules
| Rule | Type | Description |
|------|------|-------------|
| `detected` | warn | Reports task bundle detection and task count |
| `no_tasks` | deny | Bundle detected but no tasks could be extracted |
| `kind` | deny | Task `kind` must be `"Task"` |
| `name_required` | deny | Task must have `metadata.name` |
| `has_steps` | deny | Task must have at least one step |
| `step_image` | deny | Each step must have an `image` (unless using a StepAction `ref`) |

All helper rules use `_` prefix (private) to avoid being processed by EC's rule inspector.

## Usage

```bash
# Validate a task bundle image
ec validate image \
  --image quay.io/conforma/tekton-task:latest \
  --policy policies/task-bundle/policy.yaml \
  --ignore-rekor \
  --output text
```

For images without signatures, add certificate flags as needed:
```bash
ec validate image \
  --image <task-bundle-ref> \
  --policy policies/task-bundle/policy.yaml \
  --ignore-rekor \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  --output text
```

## ECP Configuration

`policy.yaml` defines the EnterpriseContractPolicy:

```yaml
description: 'POC policy for validating Tekton task bundle images'
publicKey: 'k8s://openshift-pipelines/public-key'
sources:
  - name: Task Bundle Policies
    policy:
      - ./policies/task-bundle
```

## Key Design Decisions

- **Single package**: All detection, extraction, and validation in one package avoids EC rule inspector issues with cross-package boolean helpers.
- **Private helpers**: `_` prefix keeps internal rules out of EC's rule inspection (`checkRules` only processes `warn`/`deny` + annotated rules).
- **No package-level METADATA**: Avoids helper rules being treated as "interesting" by the inspector.
- **StepAction awareness**: Steps using a `ref` (StepAction reference) are not flagged for missing `image`.

## Extending

Add new `deny`/`warn` rules in `task_bundle.rego` that iterate over `_task_definitions`:

```rego
# METADATA
# title: My new check
# custom:
#   short_name: my_check
deny contains result if {
    some task in _task_definitions
    # your validation logic
    result := {
        "code": "task_bundle.my_check",
        "msg": "...",
    }
}
```

## Future Work

- Explore reusing existing conforma/policy task policies via Rego `with` keyword
- Add step image registry validation
- Add trusted artifacts pattern validation
- Support for rule data configuration
