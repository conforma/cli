// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package vsa provides step definitions for VSA (Verification Summary Attestation) functionality testing
package vsa

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"

	"github.com/conforma/cli/acceptance/log"
)

// vsaEnvelopeFilesShouldExist checks that VSA envelope files exist in the specified directory
func vsaEnvelopeFilesShouldExist(ctx context.Context, directory string) (context.Context, error) {
	logger, _ := log.LoggerFor(ctx)

	// Expand environment variables in the directory path
	expandedDir := os.ExpandEnv(directory)

	logger.Infof("Checking for VSA envelope files in directory: %s", expandedDir)

	// Check if directory exists
	if _, err := os.Stat(expandedDir); os.IsNotExist(err) {
		return ctx, fmt.Errorf("VSA output directory does not exist: %s", expandedDir)
	}

	// Look for envelope files (should have .json extension and contain envelope data)
	files, err := filepath.Glob(filepath.Join(expandedDir, "*.json"))
	if err != nil {
		return ctx, fmt.Errorf("failed to search for VSA envelope files: %w", err)
	}

	if len(files) == 0 {
		return ctx, fmt.Errorf("no VSA envelope files found in directory: %s", expandedDir)
	}

	// Verify that at least one file contains envelope-like content
	envelopeFound := false
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Check if the file contains envelope-like structure
		contentStr := string(content)
		if strings.Contains(contentStr, "payload") && strings.Contains(contentStr, "signatures") {
			envelopeFound = true
			logger.Infof("Found VSA envelope file: %s", file)
			break
		}
	}

	if !envelopeFound {
		return ctx, fmt.Errorf("no valid VSA envelope files found in directory: %s", expandedDir)
	}

	logger.Infof("Successfully verified VSA envelope files exist in: %s", expandedDir)
	return ctx, nil
}

// multipleVSAEnvelopeFilesShouldExistForDifferentImages checks that multiple VSA envelope files exist for different images
func multipleVSAEnvelopeFilesShouldExistForDifferentImages(ctx context.Context, directory string) (context.Context, error) {
	logger, _ := log.LoggerFor(ctx)

	// Expand environment variables in the directory path
	expandedDir := os.ExpandEnv(directory)

	logger.Infof("Checking for multiple VSA envelope files for different images in directory: %s", expandedDir)

	// Check if directory exists
	if _, err := os.Stat(expandedDir); os.IsNotExist(err) {
		return ctx, fmt.Errorf("VSA output directory does not exist: %s", expandedDir)
	}

	// Look for envelope files
	files, err := filepath.Glob(filepath.Join(expandedDir, "*.json"))
	if err != nil {
		return ctx, fmt.Errorf("failed to search for VSA envelope files: %w", err)
	}

	if len(files) < 2 {
		return ctx, fmt.Errorf("expected at least 2 VSA envelope files for multiple images, found %d in directory: %s", len(files), expandedDir)
	}

	// Verify that files contain envelope-like content and are for different images
	envelopeCount := 0
	imageRefs := make(map[string]bool)

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		contentStr := string(content)
		if strings.Contains(contentStr, "payload") && strings.Contains(contentStr, "signatures") {
			envelopeCount++

			// Try to extract image reference from filename or content
			filename := filepath.Base(file)
			if strings.Contains(filename, "vsa-") {
				// Extract component name from filename pattern like "vsa-component-name.json"
				parts := strings.Split(filename, "-")
				if len(parts) > 1 {
					componentName := strings.Join(parts[1:], "-")
					componentName = strings.TrimSuffix(componentName, ".json")
					imageRefs[componentName] = true
				}
			}

			logger.Infof("Found VSA envelope file: %s", file)
		}
	}

	if envelopeCount < 2 {
		return ctx, fmt.Errorf("expected at least 2 valid VSA envelope files, found %d in directory: %s", envelopeCount, expandedDir)
	}

	if len(imageRefs) < 2 {
		return ctx, fmt.Errorf("expected VSA envelope files for at least 2 different images, found %d unique image references in directory: %s", len(imageRefs), expandedDir)
	}

	logger.Infof("Successfully verified %d VSA envelope files exist for %d different images in: %s", envelopeCount, len(imageRefs), expandedDir)
	return ctx, nil
}

// Define the key type and constant to match cli package
type key int

const (
	processStatusKey key = iota
)

// status struct to match cli package
type status struct {
	*exec.Cmd
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

// theOutputShouldContainVSAMessage checks that the command output contains the specified VSA-related text
func theOutputShouldContainVSAMessage(ctx context.Context, expectedText string) (context.Context, error) {
	logger, _ := log.LoggerFor(ctx)

	// Get the command status from context
	statusValue, ok := ctx.Value(processStatusKey).(*status)
	if !ok {
		return ctx, fmt.Errorf("no command status found in context")
	}

	// Check both stdout and stderr for the expected text
	stdout := statusValue.stdout.String()
	stderr := statusValue.stderr.String()

	if strings.Contains(stdout, expectedText) || strings.Contains(stderr, expectedText) {
		logger.Infof("Found expected VSA text in output: %s", expectedText)
		return ctx, nil
	}

	return ctx, fmt.Errorf("expected VSA text not found in output: %s\nStdout: %s\nStderr: %s", expectedText, stdout, stderr)
}

// AddStepsTo adds VSA-related Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^VSA envelope files should exist in "([^"]*)"$`, vsaEnvelopeFilesShouldExist)
	sc.Step(`^multiple VSA envelope files should exist for different images in "([^"]*)"$`, multipleVSAEnvelopeFilesShouldExistForDifferentImages)
	sc.Step(`^the output should contain "([^"]*)"$`, theOutputShouldContainVSAMessage)
}
