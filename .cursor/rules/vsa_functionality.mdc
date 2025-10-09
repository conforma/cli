# VSA (Verification Summary Attestation) Functionality

## Overview

VSA (Verification Summary Attestation) is a critical feature that creates cryptographically signed attestations containing validation metadata and policy information after successful image validation. VSAs provide tamper-evident records of what policies were used and what validation results were achieved.

## Architecture

The VSA implementation follows a layered architecture with clear separation of concerns:

### Layer 1: Core Interfaces (`interfaces.go`)
Defines the fundamental VSA interfaces for predicate generation, writing, and attestation.

### Layer 2: Service Layer (`service.go`)
High-level VSA processing orchestration for components and snapshots.

### Layer 3: Core Logic (`vsa.go`)
VSA data structures, predicate generation, and core validation logic.

### Layer 4: Attestation (`attest.go`)
DSSE envelope creation and cryptographic signing.

### Layer 5: Storage (`storage*.go`)
Abstract storage backends for VSA upload and retrieval.

### Layer 6: Retrieval (`*_retriever.go`)
VSA retrieval mechanisms from various backends.

### Layer 7: Orchestration (`orchestrator.go`)
Complex VSA processing workflows.

### Layer 8: Validation (`validator.go`)
VSA validation with policy comparison and signature verification.

### Layer 9: Command Interface (`cmd/validate/vsa.go`)
CLI for VSA validation and management.

## Core Concepts

### VSA Structure
- **Predicate**: Contains the actual validation metadata (policy, results, timestamps)
- **DSSE Envelope**: Cryptographically signed wrapper around the predicate
- **In-toto Statement**: Standardized format for supply chain attestations
- **Subject**: The image being validated (with digest)

### Key Components
- **Policy Information**: The complete policy specification used for validation
- **Validation Results**: Success/failure status, violations, warnings, successes
- **Metadata**: Timestamps, verifier information, image references
- **Public Key**: The key used for validation (embedded in VSA)

## Core Data Structures

### Predicate Structure
```go
type Predicate struct {
    Policy       ecapi.EnterpriseContractPolicySpec `json:"policy"`       // Complete policy used
    PolicySource string                             `json:"policySource"` // Original policy location
    ImageRefs    []string                           `json:"imageRefs"`    // All image references
    Timestamp    string                             `json:"timestamp"`    // RFC3339 timestamp
    Status       string                             `json:"status"`       // "passed" or "failed"
    Verifier     string                             `json:"verifier"`     // "conforma"
    Summary      VSASummary                         `json:"summary"`      // Validation results
    PublicKey    string                             `json:"publicKey"`    // PEM-encoded public key
}

type VSASummary struct {
    Violations int               `json:"violations"`
    Warnings   int               `json:"warnings"`
    Successes  int               `json:"successes"`
    Components []ComponentDetail `json:"Components"`
    Component  ComponentSummary  `json:"component"`
}

type ComponentSummary struct {
    Name           string      `json:"name"`
    ContainerImage string      `json:"containerImage"`
    Source         interface{} `json:"source"`
}

type ComponentDetail struct {
    Name       string `json:"Name"`
    ImageRef   string `json:"ImageRef"`
    Violations int    `json:"Violations"`
    Warnings   int    `json:"Warnings"`
    Successes  int    `json:"Successes"`
}
```

### Validation and Lookup Results
```go
type ValidationResult struct {
    Passed            bool   `json:"passed"`
    Message           string `json:"message,omitempty"`
    SignatureVerified bool   `json:"signature_verified,omitempty"`
}

type VSALookupResult struct {
    Found             bool
    Expired           bool
    VSA               *Predicate
    Timestamp         time.Time
    Envelope          *ssldsse.Envelope // Store the envelope for signature verification
    SignatureVerified bool              // Whether signature verification was performed and succeeded
}

type ComponentResult struct {
    ComponentName string
    ImageRef      string
    Result        *ValidationResult
    Error         error
}
```

### Identifier Types
```go
type IdentifierType int

const (
    IdentifierFile            IdentifierType = iota // Local file path
    IdentifierImageDigest                           // Container image digest (e.g., sha256:abc123...)
    IdentifierImageReference                        // Container image reference (e.g., nginx:latest)
)
```

## Core Interfaces

### PredicateGenerator Interface
```go
type PredicateGenerator[T any] interface {
    GeneratePredicate(ctx context.Context) (T, error)
}
```

### PredicateWriter Interface
```go
type PredicateWriter[T any] interface {
    WritePredicate(pred T) (string, error)
}
```

### PredicateAttestor Interface
```go
type PredicateAttestor interface {
    AttestPredicate(ctx context.Context) ([]byte, error)
    WriteEnvelope(data []byte) (string, error)
    TargetDigest() string
}
```

## Service Layer API

### VSA Service (`service.go`)

The `Service` struct encapsulates all VSA processing logic:

```go
type Service struct {
    signer       *Signer
    fs           afero.Fs
    policySource string
    policy       PublicKeyProvider
}
```

#### Key Methods:

**ProcessComponentVSA** - Creates VSA for individual components:
```go
func (s *Service) ProcessComponentVSA(ctx context.Context, report applicationsnapshot.Report, comp applicationsnapshot.Component, gitURL, digest string) (string, error)
```

**ProcessSnapshotVSA** - Creates VSA for application snapshots:
```go
func (s *Service) ProcessSnapshotVSA(ctx context.Context, report applicationsnapshot.Report) (string, error)
```

**ProcessAllVSAs** - Processes VSAs for all components and snapshot:
```go
func (s *Service) ProcessAllVSAs(ctx context.Context, report applicationsnapshot.Report, getGitURL func(applicationsnapshot.Component) string, getDigest func(applicationsnapshot.Component) (string, error)) (*VSAProcessingResult, error)
```

## VSA Generation Workflow

### 1. Component VSA Generation

**Steps:**
1. **Create Generator**: `NewGenerator(report, comp, policySource, policy)`
2. **Generate Predicate**: `GenerateAndWritePredicate(ctx, generator, writer)`
3. **Create Attestor**: `NewAttestor(predicatePath, imageRef, digest, signer)`
4. **Attest VSA**: `AttestVSA(ctx, attestor)`
5. **Return Envelope Path**: Path to the signed VSA envelope

### 2. Snapshot VSA Generation

**Steps:**
1. **Create Snapshot Generator**: `applicationsnapshot.NewSnapshotPredicateGenerator(report)`
2. **Generate Snapshot Predicate**: `GenerateAndWriteSnapshotPredicate(ctx, generator, writer)`
3. **Calculate Digest**: `applicationsnapshot.GetVSAPredicateDigest(fs, writtenPath)`
4. **Create Attestor**: `NewAttestor(predicatePath, snapshotName, digest, signer)`
5. **Attest VSA**: `AttestVSA(ctx, attestor)`
6. **Return Envelope Path**: Path to the signed snapshot VSA

## Attestation Layer (`attest.go`)

### Signer Creation
```go
func NewSigner(ctx context.Context, keyRef string, fs afero.Fs) (*Signer, error)
```

**Features:**
- Supports file paths and Kubernetes secret references
- Handles encrypted private keys with `COSIGN_PASSWORD` environment variable
- Creates DSSE wrapper for in-toto payload type

### Attestor Creation
```go
func NewAttestor(predicatePath, repo, digest string, signer *Signer) (*Attestor, error)
```

**Features:**
- Configurable predicate type URL
- Image reference and digest handling
- DSSE envelope creation

### VSA Attestation
```go
func (a Attestor) AttestPredicate(ctx context.Context) ([]byte, error)
```

**Process:**
1. Reads predicate from file
2. Creates in-toto statement with subject information
3. Signs the statement using DSSE envelope format
4. Returns signed DSSE envelope

## Storage Backends

### Storage Interface (`storage.go`)

```go
type StorageBackend interface {
    Name() string
    Upload(ctx context.Context, envelopeContent []byte) error
}

type SignerAwareUploader interface {
    StorageBackend
    UploadWithSigner(ctx context.Context, envelopeContent []byte, signer *Signer) (string, error)
}
```

### Local Filesystem Storage (`storage_local.go`)

**Format:** `local@/path/to/directory`
**Example:** `--vsa-upload local@/tmp/vsa-output`

**Features:**
- Stores VSA envelopes as files
- Creates organized directory structure
- Supports custom base paths
- No external dependencies

### Rekor Transparency Log Storage (`storage_rekor.go`)

**Format:** `rekor@https://rekor.sigstore.dev`
**Example:** `--vsa-upload rekor@https://rekor.sigstore.dev`

**Features:**
- Stores VSAs in public transparency log
- Provides tamper-evidence through public logging
- Supports custom Rekor server URLs
- Requires signer access for public key extraction
- Handles in-toto 0.0.2 entry format

### Storage Configuration

```go
func ParseStorageFlag(storageFlag string) (*StorageConfig, error)
```

**Supported formats:**
- `rekor@https://rekor.sigstore.dev`
- `local@/path/to/directory`
- `rekor?server=custom.rekor.com&timeout=30s`

## Retrieval Mechanisms

### VSA Retriever Interface

```go
type VSARetriever interface {
    RetrieveVSA(ctx context.Context, identifier string) (*ssldsse.Envelope, error)
}
```

### File-based Retrieval (`file_retriever.go`)

**Purpose:** Retrieve VSAs from local filesystem
**Features:**
- Direct file path access
- No network dependencies
- Fast local access

### Rekor-based Retrieval (`rekor_retriever.go`)

**Purpose:** Retrieve VSAs from Rekor transparency log
**Features:**
- Searches by image digest
- Handles in-toto 0.0.2 entries
- Selects latest entry by IntegratedTime
- Builds DSSE envelopes from Rekor entries

## VSA Validation and Checking

### VSA Checker (`vsa.go`)

```go
type VSAChecker struct {
    retriever VSARetriever
}
```

**Key Methods:**

**CheckExistingVSAWithVerification** - Looks up existing VSAs with optional signature verification:
```go
func (c *VSAChecker) CheckExistingVSAWithVerification(ctx context.Context, imageRef string, expirationThreshold time.Duration, verifySignature bool, publicKeyPath string) (*VSALookupResult, error)
```

**CheckExistingVSA** - Looks up existing VSAs and determines validity (backward compatibility):
```go
func (c *VSAChecker) CheckExistingVSA(ctx context.Context, imageRef string, expirationThreshold time.Duration) (*VSALookupResult, error)
```

**IsValidVSA** - Checks if VSA exists and is not expired:
```go
func (c *VSAChecker) IsValidVSA(ctx context.Context, imageRef string, expirationThreshold time.Duration) (bool, error)
```

### VSA Validation with Policy Comparison (`validator.go`)

**ValidateVSAWithPolicyComparison** - Comprehensive VSA validation with policy comparison:
```go
func ValidateVSAWithPolicyComparison(ctx context.Context, identifier string, data *ValidationData) (*ValidationResult, error)
```

**ValidationData** - Configuration for VSA validation:
```go
type ValidationData struct {
    Retriever                   VSARetriever
    VSAExpiration               time.Duration
    IgnoreSignatureVerification bool
    PublicKeyPath               string
    PolicySpec                  ecapi.EnterpriseContractPolicySpec
    EffectiveTime               string
}
```

### Policy Comparison Features

- **Policy Equivalence Checking**: Compares VSA policy with supplied policy using detailed equivalence checking
- **Signature Verification**: Optional DSSE envelope signature verification using public keys
- **Expiration Checking**: Validates VSA age against configurable thresholds
- **Detailed Error Reporting**: Provides specific policy differences and validation failures
- **Multi-format Support**: Handles both in-toto statements and direct predicate formats

## Command-Line Interface

### VSA Validation Command (`cmd/validate/vsa.go`)

**Usage:**
```bash
ec validate vsa <vsa-identifier> [flags]
```

**Supported Identifiers:**
- Image digests: `registry/image@sha256:abc123...`
- Image references: `registry/image:tag`
- File paths: `/path/to/vsa.json`

**Key Flags:**
- `--policy` - Policy configuration for comparison (required)
- `--vsa-expiration` - VSA expiration threshold (default: 168h, supports h, d, w, mo)
- `--effective-time` - Effective time for policy comparison (default: "now")
- `--workers` - Number of parallel workers (default: 5)
- `--output` - Output format specification
- `--strict` - Exit with non-zero code on validation failure (default: true)
- `--vsa-retrieval` - VSA retrieval backends (rekor@, file@)
- `--images` - Application snapshot file (alternative to single VSA)
- `--public-key` - Path to public key for signature verification (required by default)
- `--ignore-signature-verification` - Disable signature verification (default: false)

**Features:**
- Single VSA validation by identifier
- Batch VSA validation from application snapshots with parallel processing
- Multiple retrieval backends with auto-detection
- Policy comparison and validation with detailed differences
- DSSE envelope signature verification
- VSA expiration checking
- Comprehensive error reporting with unified diff format
- Support for multiple identifier types with automatic detection

## VSA Processing Workflows

### 1. VSA Generation Workflow

```
1. Create Service with signer and policy
2. For each component:
   a. Generate predicate using Generator
   b. Write predicate using Writer
   c. Create Attestor with signer
   d. Attest predicate to create DSSE envelope
   e. Upload envelope to configured storage backends
3. For application snapshot:
   a. Generate snapshot predicate
   b. Calculate digest
   c. Create snapshot attestor
   d. Attest snapshot predicate
   e. Upload snapshot envelope
```

### 2. VSA Validation Workflow

```
1. Parse VSA identifier (image digest, file path, etc.)
2. Create appropriate retriever (file, Rekor, etc.)
3. Retrieve VSA envelope from backend
4. Optional: Verify DSSE envelope signature using public key
5. Extract predicate from envelope (supports in-toto statements and direct predicates)
6. Check VSA expiration against threshold
7. Compare policies using detailed equivalence checking (if provided)
8. Return validation result with signature verification status
```

### 3. VSA Retrieval Workflow

```
1. Determine identifier type (digest, reference, file path)
2. Create appropriate retriever
3. Search for VSA entries
4. Select latest entry (for Rekor)
5. Build DSSE envelope from entry
6. Return envelope for validation
```

## Security Considerations

### Signing
- Use strong cryptographic keys for VSA signing
- Protect private keys appropriately
- Consider key rotation strategies
- **DSSE envelope signature verification is implemented and enabled by default**

### Storage
- Use HTTPS for remote storage backends
- Validate storage backend certificates
- Consider access controls for sensitive VSAs
- Implement audit logging for VSA operations

### Retrieval
- **DSSE envelope signature verification is implemented and enabled by default**
- Validate policy information integrity
- Check VSA expiration times
- Implement proper access controls
- Support for multiple signature verification methods
- Public key validation and verification

## Testing Strategy

### Unit Tests
- Test each layer independently
- Mock external dependencies
- Test error conditions and edge cases

### Integration Tests
- Test end-to-end VSA workflows
- Test with real storage backends
- Test retrieval from multiple sources

### Acceptance Tests
- Test VSA generation with real images
- Test storage with multiple backends
- Test retrieval from transparency logs
- Test policy comparison workflows

## Future Enhancements

### Signature Verification
- ✅ **DSSE envelope signature verification is implemented**
- ✅ **Public key validation is implemented**
- ✅ **Support for multiple signature verification methods is implemented**
- Enhanced signature verification with multiple key support
- Support for different signature algorithms

### Additional Storage Backends
- OCI registry storage
- Cloud storage backends (S3, GCS, Azure)
- Custom storage implementations
- Enhanced Rekor integration with custom servers

### Enhanced Retrieval
- Caching mechanisms for improved performance
- Parallel retrieval from multiple sources
- Conflict resolution strategies
- Enhanced identifier type detection
- Support for additional VSA formats

## API Reference

### Service Layer
- `NewServiceWithFS(signer, fs, policySource, policy) *Service`
- `ProcessComponentVSA(ctx, report, comp, gitURL, digest) (string, error)`
- `ProcessSnapshotVSA(ctx, report) (string, error)`
- `ProcessAllVSAs(ctx, report, getGitURL, getDigest) (*VSAProcessingResult, error)`

### Storage Layer
- `ParseStorageFlag(flag) (*StorageConfig, error)`
- `NewLocalBackend(basePath) *LocalBackend`
- `NewRekorBackend(baseURL, options) *RekorBackend`

### Retrieval Layer
- `NewFileVSARetriever(fs) *FileVSARetriever`
- `NewRekorVSARetriever(baseURL, options) *RekorVSARetriever`

### Validation Layer
- `NewVSAChecker(retriever) *VSAChecker`
- `CheckExistingVSAWithVerification(ctx, imageRef, expiration, verifySignature, publicKeyPath) (*VSALookupResult, error)`
- `CheckExistingVSA(ctx, imageRef, expiration) (*VSALookupResult, error)`
- `IsValidVSA(ctx, imageRef, expiration) (bool, error)`
- `ValidateVSAWithPolicyComparison(ctx, identifier, data) (*ValidationResult, error)`

### Utility Functions
- `DetectIdentifierType(identifier) IdentifierType`
- `IsValidVSAIdentifier(identifier) bool`
- `ParseVSAExpirationDuration(s) (time.Duration, error)`
- `ParseVSAContent(envelope) (*Predicate, error)`
- `ExtractDigestFromImageRef(imageRef) (string, error)`
- `CreateVSARetriever(vsaRetrieval, vsaIdentifier, images) (VSARetriever, error)`

This documentation accurately reflects the actual VSA implementation with its layered architecture, comprehensive API surface, sophisticated workflow management, and advanced signature verification capabilities.