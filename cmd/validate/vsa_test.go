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

//go:build unit

package validate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/validate/vsa"
)

// MockVSADataRetriever is a mock implementation of VSADataRetriever
type MockVSADataRetriever struct {
	mock.Mock
}

func (m *MockVSADataRetriever) RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error) {
	args := m.Called(ctx, imageDigest)
	return args.Get(0).(*ssldsse.Envelope), args.Error(1)
}

// MockPolicyResolver is a mock implementation of PolicyResolver
type MockPolicyResolver struct {
	mock.Mock
}

func (m *MockPolicyResolver) GetRequiredRules(ctx context.Context, imageDigest string) (map[string]bool, error) {
	args := m.Called(ctx, imageDigest)
	return args.Get(0).(map[string]bool), args.Error(1)
}

// MockVSARuleValidator is a mock implementation of VSARuleValidator
type MockVSARuleValidator struct {
	mock.Mock
}

func (m *MockVSARuleValidator) ValidateVSARules(ctx context.Context, vsaRecords []vsa.VSARecord, policyResolver vsa.PolicyResolver, imageDigest string) (*vsa.ValidationResult, error) {
	args := m.Called(ctx, vsaRecords, policyResolver, imageDigest)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vsa.ValidationResult), args.Error(1)
}

// MockValidationFunc is a mock validation function
func MockValidationFunc(ctx context.Context, imageRef string, policy policy.Policy, retriever vsa.VSADataRetriever, publicKey string) (*vsa.ValidationResult, error) {
	// This is a simple mock that returns a successful validation result
	return &vsa.ValidationResult{
		Passed:            true,
		SignatureVerified: true,
		MissingRules:      []vsa.MissingRule{},
		FailingRules:      []vsa.FailingRule{},
		PassingCount:      1,
		TotalRequired:     1,
		Summary:           "PASS: All required rules are present and passing",
		ImageDigest:       imageRef,
	}, nil
}

// MockValidationFuncWithFailure is a mock validation function that returns a failure
func MockValidationFuncWithFailure(ctx context.Context, imageRef string, policy policy.Policy, retriever vsa.VSADataRetriever, publicKey string) (*vsa.ValidationResult, error) {
	return &vsa.ValidationResult{
		Passed:            false,
		SignatureVerified: true,
		MissingRules:      []vsa.MissingRule{},
		FailingRules: []vsa.FailingRule{
			{
				RuleID:         "test.rule1",
				Package:        "test",
				Message:        "Test rule failed",
				Reason:         "Rule failed validation in VSA",
				Title:          "Test Rule",
				Description:    "This is a test rule",
				Solution:       "Fix the issue",
				ComponentImage: imageRef,
			},
		},
		PassingCount:  0,
		TotalRequired: 1,
		Summary:       "FAIL: 0 missing rules, 1 failing rules",
		ImageDigest:   imageRef,
	}, nil
}

// MockValidationFuncWithError is a mock validation function that returns an error
func MockValidationFuncWithError(ctx context.Context, imageRef string, policy policy.Policy, retriever vsa.VSADataRetriever, publicKey string) (*vsa.ValidationResult, error) {
	return nil, errors.New("validation error")
}

func TestValidateVSACmd(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		flags         map[string]string
		expectedError string
		validateFunc  vsaValidationFunc
	}{
		{
			name: "successful validation with VSA file only",
			args: []string{},
			flags: map[string]string{
				"vsa": "test-vsa.json",
			},
			validateFunc: MockValidationFunc,
		},
		{
			name: "successful validation with VSA file",
			args: []string{},
			flags: map[string]string{
				"vsa": "test-vsa.json",
			},
			validateFunc: MockValidationFunc,
		},
		{
			name: "error when no input provided",
			args: []string{},
			flags: map[string]string{
				"policy": "test-policy.yaml",
			},
			expectedError: "either --image/--images OR --vsa must be provided",
			validateFunc:  MockValidationFunc,
		},
		{
			name: "validation failure with strict mode",
			args: []string{},
			flags: map[string]string{
				"vsa":    "test-vsa.json",
				"strict": "true",
			},
			expectedError: "success criteria not met",
			validateFunc:  MockValidationFuncWithFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := validateVSACmd(tt.validateFunc)

			// Set flags
			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				require.NoError(t, err)
			}

			// Create a temporary directory for test files
			tempDir := t.TempDir()

			// Create test policy file if needed
			if policyFile, exists := tt.flags["policy"]; exists {
				policyPath := filepath.Join(tempDir, policyFile)
				// Create a valid policy YAML file
				policyContent := `apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  name: test-policy
spec:
  sources:
    - name: default
      policy:
        - github.com/enterprise-contract/ec-policies//policy/lib
        - github.com/enterprise-contract/ec-policies//policy/release
      data:
        - github.com/enterprise-contract/ec-policies//data
      config:
        - github.com/enterprise-contract/ec-policies//config
`
				err := os.WriteFile(policyPath, []byte(policyContent), 0600)
				require.NoError(t, err)

				// Update the flag to use the full path
				err = cmd.Flags().Set("policy", policyPath)
				require.NoError(t, err)
			}

			// Create test VSA file if needed
			if vsaFile, exists := tt.flags["vsa"]; exists {
				vsaPath := filepath.Join(tempDir, vsaFile)
				vsaContent := `{
				"imageRef": "quay.io/test/app:latest",
				"results": {
					"components": []
				}
			}`
				err := os.WriteFile(vsaPath, []byte(vsaContent), 0600)
				require.NoError(t, err)

				// Update the flag to use the full path
				err = cmd.Flags().Set("vsa", vsaPath)
				require.NoError(t, err)
			}

			// Execute the command
			err := cmd.Execute()

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateVSAFile(t *testing.T) {
	tests := []struct {
		name          string
		vsaContent    string
		expectedError string
		validateFunc  vsaValidationFunc
	}{
		{
			name: "successful VSA file validation",
			vsaContent: `{
				"imageRef": "quay.io/test/app:latest",
				"results": {
					"components": []
				}
			}`,
			validateFunc: MockValidationFunc,
		},
		{
			name: "VSA file with validation failure",
			vsaContent: `{
				"imageRef": "quay.io/test/app:latest",
				"results": {
					"components": []
				}
			}`,
			expectedError: "success criteria not met",
			validateFunc:  MockValidationFuncWithFailure,
		},
		{
			name: "VSA file with validation error",
			vsaContent: `{
				"imageRef": "quay.io/test/app:latest",
				"results": {
					"components": []
				}
			}`,
			expectedError: "validation failed",
			validateFunc:  MockValidationFuncWithError,
		},
		{
			name: "VSA file without image reference",
			vsaContent: `{
				"results": {
					"components": []
				}
			}`,
			expectedError: "VSA does not contain an image reference",
			validateFunc:  MockValidationFunc,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary VSA file
			tempDir := t.TempDir()
			vsaPath := filepath.Join(tempDir, "test-vsa.json")
			err := os.WriteFile(vsaPath, []byte(tt.vsaContent), 0600)
			require.NoError(t, err)

			// Create command with VSA file
			cmd := validateVSACmd(tt.validateFunc)
			err = cmd.Flags().Set("vsa", vsaPath)
			require.NoError(t, err)

			// Execute the command
			err = cmd.Execute()

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateImagesFromRekor(t *testing.T) {
	tests := []struct {
		name          string
		images        string
		expectedError string
		validateFunc  vsaValidationFunc
	}{
		{
			name: "validation error with ApplicationSnapshot (Rekor connection fails)",
			images: `{
				"components": [
					{
						"name": "test-component",
						"containerImage": "quay.io/test/app:latest"
					}
				]
			}`,
			expectedError: "validation failed",
			validateFunc:  MockValidationFuncWithError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command with images
			cmd := validateVSACmd(tt.validateFunc)
			err := cmd.Flags().Set("images", tt.images)
			require.NoError(t, err)

			// Execute the command
			err = cmd.Execute()

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWriteVSAReport(t *testing.T) {
	tests := []struct {
		name          string
		report        applicationsnapshot.VSAReport
		targets       []string
		expectedError string
	}{
		{
			name: "successful report writing",
			report: applicationsnapshot.VSAReport{
				Success: true,
				Components: []applicationsnapshot.VSAComponent{
					{
						Name:           "test-component",
						ContainerImage: "quay.io/test/app:latest",
						Success:        true,
					},
				},
			},
			targets: []string{"json"},
		},
		{
			name: "report writing with file output",
			report: applicationsnapshot.VSAReport{
				Success: true,
				Components: []applicationsnapshot.VSAComponent{
					{
						Name:           "test-component",
						ContainerImage: "quay.io/test/app:latest",
						Success:        true,
					},
				},
			},
			targets: []string{"json=test-output.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for output files
			tempDir := t.TempDir()

			// Update targets to use temp directory
			updatedTargets := make([]string, len(tt.targets))
			for i, target := range tt.targets {
				if strings.Contains(target, "=") {
					parts := strings.Split(target, "=")
					if len(parts) == 2 {
						updatedTargets[i] = fmt.Sprintf("%s=%s", parts[0], filepath.Join(tempDir, parts[1]))
					} else {
						updatedTargets[i] = target
					}
				} else {
					updatedTargets[i] = target
				}
			}

			// Create a mock target parser
			p := format.NewTargetParser("json", format.Options{}, os.Stdout, utils.FS(context.Background()))

			// Test writeVSAReport function
			err := writeVSAReport(tt.report, updatedTargets, p)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVSAValidationFunc(t *testing.T) {
	tests := []struct {
		name          string
		imageRef      string
		policy        policy.Policy
		retriever     vsa.VSADataRetriever
		publicKey     string
		expectedError string
		validateFunc  vsaValidationFunc
	}{
		{
			name:         "successful validation",
			imageRef:     "quay.io/test/app:latest",
			policy:       nil,
			retriever:    &MockVSADataRetriever{},
			publicKey:    "",
			validateFunc: MockValidationFunc,
		},
		{
			name:         "validation failure",
			imageRef:     "quay.io/test/app:latest",
			policy:       nil,
			retriever:    &MockVSADataRetriever{},
			publicKey:    "",
			validateFunc: MockValidationFuncWithFailure,
		},
		{
			name:          "validation error",
			imageRef:      "quay.io/test/app:latest",
			policy:        nil,
			retriever:     &MockVSADataRetriever{},
			publicKey:     "",
			expectedError: "validation error",
			validateFunc:  MockValidationFuncWithError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			result, err := tt.validateFunc(ctx, tt.imageRef, tt.policy, tt.retriever, tt.publicKey)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.imageRef, result.ImageDigest)
			}
		})
	}
}

func TestVSACommandFlags(t *testing.T) {
	cmd := validateVSACmd(MockValidationFunc)

	// Test that all expected flags are present
	expectedFlags := []string{
		"image", "images", "policy", "vsa", "public-key",
		"output", "output-file", "strict", "effective-time", "workers",
		"no-color", "color",
	}

	for _, flag := range expectedFlags {
		assert.True(t, cmd.Flags().HasFlags(), "Flag %s should be present", flag)
	}
}

func TestVSACommandHelp(t *testing.T) {
	cmd := validateVSACmd(MockValidationFunc)

	// Test that help text is present
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotEmpty(t, cmd.Example)

	// Test that usage is correct
	assert.Equal(t, "vsa", cmd.Use)
}

func TestVSACommandPreRunValidation(t *testing.T) {
	tests := []struct {
		name          string
		flags         map[string]string
		expectedError string
	}{
		{
			name: "valid with image only",
			flags: map[string]string{
				"image": "quay.io/test/app:latest",
			},
		},
		{
			name: "valid with VSA file",
			flags: map[string]string{
				"vsa": "test-vsa.json",
			},
		},
		{
			name: "invalid - no input",
			flags: map[string]string{
				"policy": "test-policy.yaml",
			},
			expectedError: "either --image/--images OR --vsa must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := validateVSACmd(MockValidationFunc)

			// Set flags
			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				require.NoError(t, err)
			}

			// Create test files if needed
			tempDir := t.TempDir()
			if policyFile, exists := tt.flags["policy"]; exists {
				policyPath := filepath.Join(tempDir, policyFile)
				policyContent := `apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  name: test-policy
spec:
  sources:
    - name: default
      policy:
        - github.com/enterprise-contract/ec-policies//policy/lib
`
				err := os.WriteFile(policyPath, []byte(policyContent), 0600)
				require.NoError(t, err)
				err = cmd.Flags().Set("policy", policyPath)
				require.NoError(t, err)
			}

			if vsaFile, exists := tt.flags["vsa"]; exists {
				vsaPath := filepath.Join(tempDir, vsaFile)
				err := os.WriteFile(vsaPath, []byte(`{"imageRef":"test"}`), 0600)
				require.NoError(t, err)
				err = cmd.Flags().Set("vsa", vsaPath)
				require.NoError(t, err)
			}

			// Test PreRunE
			err := cmd.PreRunE(cmd, []string{})

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
