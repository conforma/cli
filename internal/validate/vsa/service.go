// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// VSAProcessingResult contains the results of VSA processing
type VSAProcessingResult struct {
	ComponentEnvelopes map[string]string // imageRef -> envelopePath
	SnapshotEnvelope   string
}

// Service encapsulates all VSA processing logic for both components and snapshots
type Service struct {
	signer *Signer
	fs     afero.Fs
}

// NewServiceWithFS creates a new VSA service with the given signer and filesystem
func NewServiceWithFS(signer *Signer, fs afero.Fs) *Service {
	return &Service{
		signer: signer,
		fs:     fs,
	}
}

// ProcessComponentVSA processes VSA generation, writing, and attestation for a single component
func (s *Service) ProcessComponentVSA(ctx context.Context, report applicationsnapshot.Report, comp applicationsnapshot.Component, gitURL, digest string) (string, error) {
	generator := NewGenerator(report, comp)
	writer := &Writer{
		FS:            s.fs,
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}

	// Generate and write VSA predicate
	writtenPath, err := GenerateAndWriteVSA(ctx, generator, writer)
	if err != nil {
		return "", fmt.Errorf("failed to generate and write component VSA: %w", err)
	}

	// Create attestor and attest VSA
	attestor, err := NewAttestor(writtenPath, gitURL, digest, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to create component attestor: %w", err)
	}

	envelopePath, err := AttestVSA(ctx, attestor)
	if err != nil {
		return "", fmt.Errorf("failed to attest component VSA: %w", err)
	}

	log.WithFields(log.Fields{
		"envelope_path": envelopePath,
	}).Info("[VSA] Component VSA attested and envelope written")
	return envelopePath, nil
}

// ProcessSnapshotVSA processes VSA generation, writing, and attestation for the application snapshot
func (s *Service) ProcessSnapshotVSA(ctx context.Context, report applicationsnapshot.Report) (string, error) {
	generator := applicationsnapshot.NewSnapshotVSAGenerator(report)
	writer := applicationsnapshot.NewSnapshotVSAWriter()
	writer.FS = s.fs

	// Generate and write VSA predicate
	writtenPath, err := GenerateAndWriteVSA(ctx, generator, writer)
	if err != nil {
		return "", fmt.Errorf("failed to generate and write snapshot VSA: %w", err)
	}

	// Calculate digest for the snapshot VSA predicate
	digest, err := applicationsnapshot.GetVSAPredicateDigest(s.fs, writtenPath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate digest for snapshot VSA: %w", err)
	}

	// Create attestor and attest VSA
	attestor, err := NewAttestor(writtenPath, "", digest, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot attestor: %w", err)
	}

	envelopePath, err := AttestVSA(ctx, attestor)
	if err != nil {
		return "", fmt.Errorf("failed to attest snapshot VSA: %w", err)
	}

	log.WithFields(log.Fields{
		"envelope_path": envelopePath,
	}).Info("[VSA] Snapshot VSA attested and envelope written")
	return envelopePath, nil
}

// ProcessAllVSAs processes VSAs for all components and the snapshot, returning envelope paths
func (s *Service) ProcessAllVSAs(ctx context.Context, report applicationsnapshot.Report, getGitURL func(applicationsnapshot.Component) string, getDigest func(applicationsnapshot.Component) (string, error)) (*VSAProcessingResult, error) {
	result := &VSAProcessingResult{
		ComponentEnvelopes: make(map[string]string),
	}

	// Process VSAs for all components
	for _, comp := range report.Components {
		gitURL := getGitURL(comp)
		digest, err := getDigest(comp)
		if err != nil {
			log.Errorf("Failed to get digest for component %s: %v", comp.ContainerImage, err)
			continue
		}

		envelopePath, err := s.ProcessComponentVSA(ctx, report, comp, gitURL, digest)
		if err != nil {
			log.Errorf("Failed to process VSA for component %s: %v", comp.ContainerImage, err)
			continue
		}

		result.ComponentEnvelopes[comp.ContainerImage] = envelopePath
	}

	// Process VSA for the snapshot
	snapshotEnvelopePath, err := s.ProcessSnapshotVSA(ctx, report)
	if err != nil {
		log.Errorf("Failed to process snapshot VSA: %v", err)
		return result, err
	}

	result.SnapshotEnvelope = snapshotEnvelopePath

	return result, nil
}

// VSAService orchestrates VSA validation
type VSAService struct {
	retriever      VSARetriever
	validator      VSARuleValidator
	policyResolver PolicyResolver
	fs             afero.Fs
}

// NewVSAService creates a new VSA service with dependency injection
func NewVSAService(
	retriever VSARetriever,
	validator VSARuleValidator,
	policyResolver PolicyResolver,
	fs afero.Fs,
) *VSAService {
	return &VSAService{
		retriever:      retriever,
		validator:      validator,
		policyResolver: policyResolver,
		fs:             fs,
	}
}

// ValidateVSA validates VSA records against policy
func (s *VSAService) ValidateVSA(ctx context.Context, imageRef, vsaPath string) (*ValidationResult, error) {
	// Extract digest from image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	digest := ref.Identifier()

	// Retrieve VSA records
	var vsaRecords []VSARecord
	if vsaPath != "" {
		// Use file retriever
		fileRetriever := NewFileVSARetriever(s.fs)
		vsaRecords, err = fileRetriever.RetrieveVSA(ctx, vsaPath)
	} else {
		// Use Rekor retriever
		vsaRecords, err = s.retriever.RetrieveVSA(ctx, digest)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA records: %w", err)
	}

	if len(vsaRecords) == 0 {
		return nil, fmt.Errorf("no VSA records found")
	}

	// Validate VSA records
	result, err := s.validator.ValidateVSARules(ctx, vsaRecords, s.policyResolver, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to validate VSA: %w", err)
	}

	return result, nil
}
