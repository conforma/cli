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
	"strings"

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
	signer       *Signer
	fs           afero.Fs
	policySource string
	policy       PublicKeyProvider
	unsignedMode bool // Whether to create unsigned VSAs (raw predicates)
}

// NewServiceWithFS creates a new VSA service with the given signer and filesystem
func NewServiceWithFS(signer *Signer, fs afero.Fs, policySource string, policy PublicKeyProvider) *Service {
	return &Service{
		signer:       signer,
		fs:           fs,
		policySource: policySource,
		policy:       policy,
		unsignedMode: false, // Default to signed mode
	}
}

// NewServiceWithOptions creates a new VSA service with explicit options including unsigned mode
func NewServiceWithOptions(signer *Signer, fs afero.Fs, policySource string, policy PublicKeyProvider, unsignedMode bool) *Service {
	return &Service{
		signer:       signer,
		fs:           fs,
		policySource: policySource,
		policy:       policy,
		unsignedMode: unsignedMode,
	}
}

// ProcessComponentVSA processes VSA generation, writing, and attestation for a single component
func (s *Service) ProcessComponentVSA(ctx context.Context, report applicationsnapshot.Report, comp applicationsnapshot.Component, gitURL, digest string) (string, error) {
	generator := NewGenerator(report, comp, s.policySource, s.policy)
	writer := &Writer{
		FS:            s.fs,
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}

	// Generate and write Predicate (new format)
	writtenPath, err := GenerateAndWritePredicate(ctx, generator, writer)
	if err != nil {
		return "", fmt.Errorf("failed to generate and write component Predicate: %w", err)
	}

	// If unsigned mode is enabled, return the raw predicate path
	if s.unsignedMode {
		log.WithFields(log.Fields{
			"predicate_path": writtenPath,
		}).Info("[VSA] Component Predicate written (signing disabled)")
		return writtenPath, nil
	}

	// Create attestor and attest Predicate
	// Use the image reference (without digest) as the repo for the subject name
	imageRef := comp.ContainerImage
	if idx := strings.LastIndex(imageRef, "@"); idx != -1 {
		imageRef = imageRef[:idx] // Remove digest to get just the image reference
	}
	attestor, err := NewAttestor(writtenPath, imageRef, digest, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to create component attestor: %w", err)
	}

	envelopePath, err := AttestVSA(ctx, attestor)
	if err != nil {
		return "", fmt.Errorf("failed to attest component Predicate: %w", err)
	}

	log.WithFields(log.Fields{
		"envelope_path": envelopePath,
	}).Info("[VSA] Component Predicate attested and envelope written")
	return envelopePath, nil
}

// ProcessSnapshotVSA processes VSA generation, writing, and attestation for the application snapshot
func (s *Service) ProcessSnapshotVSA(ctx context.Context, report applicationsnapshot.Report) (string, error) {
	generator := applicationsnapshot.NewSnapshotPredicateGenerator(report)
	writer := applicationsnapshot.NewSnapshotPredicateWriter()
	writer.FS = s.fs

	// Generate and write Predicate (new format)
	writtenPath, err := GenerateAndWriteSnapshotPredicate(ctx, generator, writer)
	if err != nil {
		return "", fmt.Errorf("failed to generate and write snapshot Predicate: %w", err)
	}

	// Calculate digest for the snapshot Predicate
	digest, err := applicationsnapshot.GetVSAPredicateDigest(s.fs, writtenPath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate digest for snapshot Predicate: %w", err)
	}

	// If unsigned mode is enabled, return the raw predicate path
	if s.unsignedMode {
		log.WithFields(log.Fields{
			"predicate_path": writtenPath,
		}).Info("[VSA] Snapshot Predicate written (signing disabled)")
		return writtenPath, nil
	}

	// Create attestor and attest Predicate
	// Use a meaningful name for the snapshot subject
	snapshotName := "application-snapshot"
	if report.Snapshot != "" {
		snapshotName = report.Snapshot
	}
	attestor, err := NewAttestor(writtenPath, snapshotName, digest, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot attestor: %w", err)
	}

	envelopePath, err := AttestVSA(ctx, attestor)
	if err != nil {
		return "", fmt.Errorf("failed to attest snapshot Predicate: %w", err)
	}

	log.WithFields(log.Fields{
		"envelope_path": envelopePath,
	}).Info("[VSA] Snapshot Predicate attested and envelope written")
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
