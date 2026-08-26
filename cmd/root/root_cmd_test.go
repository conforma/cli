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

package root

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/http"
)

func TestGlobalTimeout(t *testing.T) {
	tests := []struct {
		name           string
		timeoutFlag    string
		expectedValue  time.Duration
		expectedString string
	}{
		{
			name:           "default timeout",
			timeoutFlag:    "",
			expectedValue:  5 * time.Minute,
			expectedString: "5m0s",
		},
		{
			name:           "custom timeout in hours",
			timeoutFlag:    "100h",
			expectedValue:  100 * time.Hour,
			expectedString: "100h0m0s",
		},
		{
			name:           "custom timeout in minutes",
			timeoutFlag:    "30m",
			expectedValue:  30 * time.Minute,
			expectedString: "30m0s",
		},
		{
			name:           "zero timeout",
			timeoutFlag:    "0",
			expectedValue:  0,
			expectedString: "0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset globalTimeout to default value before each test
			globalTimeout = 5 * time.Minute

			cmd := NewRootCmd()
			if tt.timeoutFlag != "" {
				cmd.SetArgs([]string{"--timeout", tt.timeoutFlag})
			}

			// Execute the command to trigger flag parsing
			err := cmd.Execute()
			assert.NoError(t, err)

			// Verify the timeout value
			assert.Equal(t, tt.expectedValue, globalTimeout)
			assert.Equal(t, tt.expectedString, globalTimeout.String())
		})
	}
}

func TestGlobalTimeoutDisabledInServerMode(t *testing.T) {
	globalTimeout = 5 * time.Minute

	var capturedCtx context.Context
	cmd := NewRootCmd()

	// Synthetic command tree to avoid pulling in the real validate input
	// command and its dependencies. If the real flag or command name changes,
	// the server-mode acceptance tests would catch it.
	validate := &cobra.Command{Use: "validate"}
	input := &cobra.Command{
		Use: "input",
		Run: func(cmd *cobra.Command, _ []string) {
			capturedCtx = cmd.Context()
		},
	}
	var server bool
	input.Flags().BoolVar(&server, "server", false, "")
	validate.AddCommand(input)
	cmd.AddCommand(validate)

	cmd.SetArgs([]string{"validate", "input", "--server"})

	err := cmd.Execute()
	assert.NoError(t, err)
	// The package-level variable must not be mutated.
	assert.Equal(t, 5*time.Minute, globalTimeout)
	// The execution context must not carry a deadline.
	_, hasDeadline := capturedCtx.Deadline()
	assert.False(t, hasDeadline)
}

func TestRetryConfigurationFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedConfig http.RetryConfig
	}{
		{
			name: "default retry configuration",
			args: []string{},
			expectedConfig: http.RetryConfig{
				MaxWait:  3 * time.Second,
				MaxRetry: 3,
				Duration: 1 * time.Second,
				Factor:   2.0,
				Jitter:   0.1,
			},
		},
		{
			name: "custom retry configuration",
			args: []string{
				"--retry-max-wait", "2s",
				"--retry-max-retry", "5",
				"--retry-duration", "500ms",
				"--retry-factor", "1.5",
				"--retry-jitter", "0.2",
			},
			expectedConfig: http.RetryConfig{
				MaxWait:  2 * time.Second,
				MaxRetry: 5,
				Duration: 500 * time.Millisecond,
				Factor:   1.5,
				Jitter:   0.2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to default values
			retryMaxWait = 3 * time.Second
			retryMaxRetry = 3
			retryDuration = 1 * time.Second
			retryFactor = 2.0
			retryJitter = 0.1

			cmd := NewRootCmd()
			if len(tt.args) > 0 {
				cmd.SetArgs(append(tt.args, "version"))
			} else {
				cmd.SetArgs([]string{"version"})
			}

			// Execute the command to trigger flag parsing and configuration
			err := cmd.Execute()
			assert.NoError(t, err)

			// Verify the configuration was applied by checking the actual values
			// The configuration is applied in PersistentPreRun, so we need to check
			// that the flags were parsed correctly
			if len(tt.args) > 0 {
				// For custom configuration, verify that the flags were parsed
				assert.Equal(t, tt.expectedConfig.MaxWait, retryMaxWait)
				assert.Equal(t, tt.expectedConfig.MaxRetry, retryMaxRetry)
				assert.Equal(t, tt.expectedConfig.Duration, retryDuration)
				assert.Equal(t, tt.expectedConfig.Factor, retryFactor)
				assert.Equal(t, tt.expectedConfig.Jitter, retryJitter)
			}
		})
	}
}
