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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

// mockValidate is a helper function that returns a specified Output and error for testing.
func mockValidate(out *output.Output, err error) InputValidationFunc {
	return func(_ context.Context, fpath string, _ policy.Policy, _ bool) (*output.Output, error) {
		// This function ignores the actual file content and always returns the provided output and error.
		return out, err
	}
}

func setUpValidateInputCmd(validate InputValidationFunc, fs afero.Fs) (*cobra.Command, *bytes.Buffer) {
	// Create the parent validate command to get the persistent flags
	validateCmd := NewValidateCmd()
	cmd := validateInputCmd(validate)
	validateCmd.AddCommand(cmd)

	// Create a fake client and context with a memory filesystem.
	client := fake.FakeClient{}
	ctx := utils.WithFS(context.Background(), fs)
	ctx = oci.WithClient(ctx, &client)
	validateCmd.SetContext(ctx)

	var out bytes.Buffer
	validateCmd.SetOut(&out)

	return validateCmd, &out
}

func Test_ValidateInputCmd_SuccessSingleFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Write a dummy file to simulate input
	require.NoError(t, afero.WriteFile(fs, "/input.yaml", []byte("some: data"), 0644))

	// Mock validator: returns success with no violations, one success result.
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Successes: []evaluator.Result{
					{Message: "Everything looks great!"},
				},
			},
		},
	}

	cmd, buf := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/input.yaml",
		"--policy", `{"publicKey": "testkey"}`,
		"--output", "json", // Explicitly request JSON output
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.NoError(t, err)

	// Parse the JSON output
	var outJSON map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &outJSON)
	assert.NoError(t, err)

	// Ensure success is true
	assert.True(t, outJSON["success"].(bool))

	inputFiles, ok := outJSON["filepaths"].([]interface{})
	if !ok {
		t.Fatal("expected 'filepaths' key in output")
	}
	assert.Len(t, inputFiles, 1)
	inputObj := inputFiles[0].(map[string]interface{})
	assert.Equal(t, "/input.yaml", inputObj["filepath"])
	assert.True(t, inputObj["success"].(bool))
}

func Test_ValidateInputCmd_SuccessMultipleFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/input1.yaml", []byte("some: data"), 0644))
	require.NoError(t, afero.WriteFile(fs, "/input2.yaml", []byte("other: data"), 0644))

	// Mock validator: always returns success.
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Successes: []evaluator.Result{
					{Message: "Pass"},
				},
			},
		},
	}

	cmd, buf := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/input1.yaml",
		"--file", "/input2.yaml",
		"--policy", `{"name":"Default","description":"Stuff and things","sources":[{"name":"Default","policy":["/bacon/and/eggs/policy/lib","/bacon/and/eggs/policy/release"],"data":["/bacon/and/eggs/example/data"],"config":{"include":["sbom_cyclonedx"],"exclude":[]}}]}`,
		"--output", "json", // Explicitly request JSON output
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.NoError(t, err)

	var outJSON map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &outJSON)
	assert.NoError(t, err)
	assert.True(t, outJSON["success"].(bool))

	inputFiles, ok := outJSON["filepaths"].([]interface{})
	if !ok {
		t.Fatal("expected 'filepaths' key in output")
	}
	assert.Len(t, inputFiles, 2)

	// Verify sorting by filepath descending as per code
	filePaths := []string{}
	for _, input := range inputFiles {
		f := input.(map[string]interface{})["filepath"].(string)
		filePaths = append(filePaths, f)
	}
	sorted := append([]string{}, filePaths...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] > sorted[j]
	})
	assert.Equal(t, sorted, filePaths)
}

func Test_ValidateInputCmd_Failure(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/bad.yaml", []byte("invalid"), 0644))

	// Mock validator: returns an error
	cmd, _ := setUpValidateInputCmd(mockValidate(nil, errors.New("validation failed")), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/bad.yaml",
		"--policy", `{"publicKey": "testkey"}`,
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.EqualError(t, err, "error validating file /bad.yaml: validation failed")
}

func Test_ValidateInputCmd_StrictMode(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("some: data"), 0644))

	// Mock validator: returns no error, but a violation.
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Failures: []evaluator.Result{
					{Message: "Some violation"},
				},
			},
		},
	}

	cmd, _ := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/file.yaml",
		"--policy", `{"publicKey": "testkey"}`,
		"--strict", "true",
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "success criteria not met")
}

func Test_ValidateInputCmd_NonStrictMode(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("some: data"), 0644))

	// Mock validator: returns no error but a violation (should not cause non-zero exit in non-strict mode).
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Failures: []evaluator.Result{
					{Message: "Some violation"},
				},
			},
		},
	}

	cmd, _ := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/file.yaml",
		"--policy", `{"publicKey": "testkey"}`,
		"--strict", "false",
	})

	utils.SetTestRekorPublicKey(t)

	// Capture output for assertions
	outputBuffer := &bytes.Buffer{}
	cmd.SetOut(outputBuffer)
	cmd.SetErr(outputBuffer)

	// Execute the command
	err := cmd.Execute()

	// Ensure no error is returned in non-strict mode
	assert.Error(t, err)

	// Check that the output mentions violations, but the command succeeds
	output := outputBuffer.String()
	assert.Contains(t, output, "Some violation")
	assert.Contains(t, output, "success criteria not met")
}

func Test_ValidateInputCmd_NoPolicyProvided(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("some: data"), 0644))

	cmd, _ := setUpValidateInputCmd(nil, fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/file.yaml",
	})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag(s) \"policy\" not set")
}

func Test_ValidateInputCmd_NoFileProvided(t *testing.T) {
	cmd, _ := setUpValidateInputCmd(nil, afero.NewMemMapFs())
	cmd.SetArgs([]string{
		"input",
		"--policy", `{"publicKey":"testkey"}`,
	})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag(s) \"file\" not set")
}

func Test_ValidateInputCmd_PolicyParsingError(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("some: data"), 0644))

	cmd, _ := setUpValidateInputCmd(nil, fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/file.yaml",
		"--policy", `{"invalidjson":"}`,
	})

	err := cmd.Execute()
	assert.Error(t, err)
	// Adjust the assertion if a different error message is thrown by your policy parser
	assert.Contains(t, err.Error(), "unable to parse EnterpriseContractPolicySpec")
}

func Test_ValidateInputCmd_EmptyPolicyFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("data"), 0644))
	require.NoError(t, afero.WriteFile(fs, "/policy.yaml", []byte{}, 0644))

	cmd, _ := setUpValidateInputCmd(nil, fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/file.yaml",
		"--policy", "/policy.yaml",
	})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file /policy.yaml is empty")
}

func Test_ValidateInputCmd_ShowWarningsFlag(t *testing.T) {
	// Create a validator that returns warnings
	warningValidator := func(_ context.Context, fpath string, _ policy.Policy, _ bool) (*output.Output, error) {
		return &output.Output{
			PolicyCheck: []evaluator.Outcome{
				{
					Warnings: []evaluator.Result{
						{
							Message: "This is a warning message",
							Metadata: map[string]interface{}{
								"code":  "warning.test",
								"title": "Test Warning",
							},
						},
					},
				},
			},
		}, nil
	}

	cases := []struct {
		name             string
		args             []string
		expectedWarnings bool
	}{
		{
			name:             "default behavior (show-warnings=true)",
			args:             []string{"input", "--file", "/file.yaml", "--policy", `{"publicKey": "testkey"}`},
			expectedWarnings: true,
		},
		{
			name:             "explicit show-warnings=true",
			args:             []string{"input", "--file", "/file.yaml", "--policy", `{"publicKey": "testkey"}`, "--show-warnings=true"},
			expectedWarnings: true,
		},
		{
			name:             "show-warnings=false",
			args:             []string{"input", "--file", "/file.yaml", "--policy", `{"publicKey": "testkey"}`, "--show-warnings=false"},
			expectedWarnings: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(fs, "/file.yaml", []byte("some: data"), 0644))

			cmd, buf := setUpValidateInputCmd(warningValidator, fs)
			args := append(c.args, "--output", "json") // Explicitly request JSON output
			cmd.SetArgs(args)

			utils.SetTestRekorPublicKey(t)
			err := cmd.Execute()
			assert.NoError(t, err)

			// Parse the JSON output
			var outJSON map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &outJSON)
			assert.NoError(t, err)

			inputFiles, ok := outJSON["filepaths"].([]interface{})
			if !ok {
				t.Fatal("expected 'filepaths' key in output")
			}
			assert.Len(t, inputFiles, 1)
			inputObj := inputFiles[0].(map[string]interface{})

			// Check if warnings are present in the output
			warnings, hasWarnings := inputObj["warnings"].([]interface{})
			if c.expectedWarnings {
				assert.True(t, hasWarnings, "Warnings should be present in output when show-warnings=true")
				assert.Len(t, warnings, 1, "Should have one warning")
				if len(warnings) > 0 {
					warningObj := warnings[0].(map[string]interface{})
					assert.Equal(t, "This is a warning message", warningObj["msg"])
				}
			} else {
				// When show-warnings=false, warnings should not be in the JSON output
				// (they're filtered out at the component level)
				assert.False(t, hasWarnings, "Warnings should NOT be present in output when show-warnings=false")
			}
		})
	}
}

func Test_ValidateInputCmd_DefaultTextOutput(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/input.yaml", []byte("some: data"), 0644))

	// Mock validator: returns success with no violations, one success result.
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Successes: []evaluator.Result{
					{
						Message: "Everything looks great!",
						Metadata: map[string]interface{}{
							"code": "policy.nice",
						},
					},
				},
			},
		},
	}

	cmd, buf := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/input.yaml",
		"--policy", `{"publicKey": "testkey"}`,
		// No --output flag, should default to text
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	// Verify text output format
	assert.Contains(t, output, "Success: true")
	assert.Contains(t, output, "Result: SUCCESS")
	assert.Contains(t, output, "Violations: 0")
	assert.Contains(t, output, "Input File: /input.yaml")
	// Results section should not appear when there are only successes and showSuccesses=false
	assert.NotContains(t, output, "Results:")
}

func Test_ValidateInputCmd_TextOutputWithShowSuccesses(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/input.yaml", []byte("some: data"), 0644))

	// Mock validator: returns success with one success result.
	outMock := &output.Output{
		PolicyCheck: []evaluator.Outcome{
			{
				Successes: []evaluator.Result{
					{
						Message: "Everything looks great!",
						Metadata: map[string]interface{}{
							"code": "policy.nice",
						},
					},
				},
			},
		},
	}

	cmd, buf := setUpValidateInputCmd(mockValidate(outMock, nil), fs)
	cmd.SetArgs([]string{
		"input",
		"--file", "/input.yaml",
		"--policy", `{"publicKey": "testkey"}`,
		"--show-successes",
	})

	utils.SetTestRekorPublicKey(t)
	err := cmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	// Verify text output format with successes shown
	assert.Contains(t, output, "Success: true")
	assert.Contains(t, output, "Result: SUCCESS")
	assert.Contains(t, output, "Successes: 1")
	assert.Contains(t, output, "Input File: /input.yaml")
	assert.Contains(t, output, "Results:")
	assert.Contains(t, output, "[Success] policy.nice")
}
