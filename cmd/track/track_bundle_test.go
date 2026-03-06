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

package track

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/cmd/root"
	"github.com/conforma/cli/internal/utils"
)

func Test_TrackBundleCommand(t *testing.T) {
	cases := []struct {
		name               string
		args               []string
		expectOutput       string
		expectUrls         []string
		expectPrune        bool
		expectInput        string
		expectStdout       bool
		expectImageOutput  bool
		expectFreshen      bool
		expectInEffectDays int
	}{
		{
			name: "simple",
			args: []string{
				"--bundle",
				"registry/image:tag",
			},
			expectPrune:  true,
			expectUrls:   []string{"registry/image:tag"},
			expectStdout: true,
		},
		{
			name: "with output file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--output",
				"output-1.json",
			},
			expectOutput: "output-1.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectStdout: false,
		},
		{
			name: "with input file",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-3.json",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "input-3.json",
			expectStdout: true,
		},
		{
			name: "with input file replace",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"tracker-3.json",
				"--replace",
			},
			expectOutput: "tracker-3.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "tracker-3.json",
			expectStdout: true,
		},
		{
			name: "with input and output files",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-4.json",
				"--output",
				"output-4.json",
			},
			expectOutput: "output-4.json",
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectInput:  "input-4.json",
			expectStdout: false,
		},
		{
			name: "with explicit prune",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--prune",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  true,
			expectStdout: true,
		},
		{
			name: "without prune",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--prune=false",
			},
			expectUrls:   []string{"registry/image:tag"},
			expectPrune:  false,
			expectStdout: true,
		},
		{
			name: "using OCI",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"oci:registry.io/repository/image:tag",
				"--output",
				"oci:registry.io/repository/image:new_tag",
			},
			expectInput:       "registry.io/repository/image:tag",
			expectOutput:      "registry.io/repository/image:new_tag",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectStdout:      false,
			expectImageOutput: true,
		},
		{
			name: "using OCI for pull",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"oci:registry.io/repository/image:tag",
			},
			expectInput:       "registry.io/repository/image:tag",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectStdout:      true,
			expectImageOutput: true,
		},
		{
			name: "using OCI for push",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--input",
				"input-5.json",
				"--output",
				"oci:registry.io/repository/image:tag",
			},
			expectInput:       "input-5.json",
			expectPrune:       true,
			expectUrls:        []string{"registry/image:tag"},
			expectOutput:      "registry.io/repository/image:tag",
			expectStdout:      false,
			expectImageOutput: true,
		},
		{
			name: "tracking git references",
			args: []string{
				"--git",
				"git+https://github.com/konflux-ci/build-definitions.git//task/buildah/0.1/buildah.yaml@3672a457e3e89c0591369f609eba727b8e84108f",
			},
			expectStdout: true,
			expectPrune:  true,
			expectUrls:   []string{"git+https://github.com/konflux-ci/build-definitions.git//task/buildah/0.1/buildah.yaml@3672a457e3e89c0591369f609eba727b8e84108f"},
		},
		{
			name: "custom effective duration",
			args: []string{
				"--bundle",
				"registry/image:tag",
				"--in-effect-days",
				"666",
			},
			expectUrls:         []string{"registry/image:tag"},
			expectStdout:       true,
			expectPrune:        true,
			expectInEffectDays: 666,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.TODO(), fs)
			inputData := []byte(fmt.Sprintf(`{"file": "%s"}`, c.expectInput))

			if c.expectInput != "" {
				err := afero.WriteFile(fs, c.expectInput, inputData, 0o777)
				assert.NoError(t, err)
			}
			testOutput := `{"test": true}`
			track := func(_ context.Context, urls []string, input []byte, prune bool, freshen bool, inEffectDays int) ([]byte, error) {
				assert.Equal(t, c.expectUrls, urls)
				if c.expectInput != "" {
					assert.Equal(t, inputData, input)
				}
				assert.Equal(t, c.expectPrune, prune)
				assert.Equal(t, c.expectFreshen, freshen)
				if c.expectInEffectDays != 0 {
					assert.Equal(t, c.expectInEffectDays, inEffectDays)
				} else {
					assert.Equal(t, 60, inEffectDays)
				}
				return []byte(testOutput), nil
			}
			pullImage := func(_ context.Context, imageRef string) ([]byte, error) {
				assert.Equal(t, c.expectInput, imageRef)
				return inputData, nil
			}
			pushImage := func(_ context.Context, imageRef string, data []byte, invocation string) error {
				assert.Equal(t, c.expectOutput, imageRef)
				assert.Equal(t, testOutput, string(data))
				assert.NotEmpty(t, invocation) // in tests this will be the cmd.test in temp directory, counting on os.Args to be correct when ec is invoked
				return nil
			}
			completeArgs := append([]string{"track", "bundle"}, c.args...)
			trackBundleCmd := trackBundleCmd(track, pullImage, pushImage)
			trackCmd := NewTrackCmd()
			trackCmd.AddCommand(trackBundleCmd)
			cmd := root.NewRootCmd()
			cmd.AddCommand(trackCmd)
			cmd.SetContext(ctx)
			cmd.SetArgs(completeArgs)
			var out bytes.Buffer
			cmd.SetOut(&out)
			err := cmd.Execute()
			assert.NoError(t, err)

			if c.expectStdout {
				assert.JSONEq(t, testOutput, out.String())
			} else {
				assert.Empty(t, out.String())
			}

			if !c.expectImageOutput && c.expectOutput != "" {
				actualOutput, err := afero.ReadFile(fs, c.expectOutput)
				assert.NoError(t, err)
				assert.JSONEq(t, testOutput, string(actualOutput))
			}
		})
	}
}

// TestBundleCommandHelp tests that the command help reflects the new expires_on behavior
func TestBundleCommandHelp(t *testing.T) {
	trackBundleCmd := trackBundleCmd(nil, nil, nil)

	// Verify the long description mentions expires_on
	assert.Contains(t, trackBundleCmd.Long, "expires_on",
		"Command help should mention expires_on")

	// Verify it explains the new behavior
	assert.Contains(t, trackBundleCmd.Long, "expiration date is added",
		"Command help should explain that expiration dates are added")

	// Verify pruning explanation is updated
	assert.Contains(t, trackBundleCmd.Long, "expired entries are removed",
		"Command help should explain pruning removes expired entries")

	// Verify the in-effect-days flag is documented
	foundFlag := false
	trackBundleCmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "in-effect-days" {
			foundFlag = true
			assert.Equal(t, "60", flag.DefValue, "Default value should be 60")
		}
	})
	assert.True(t, foundFlag, "in-effect-days flag should exist")
}

func TestPreRunE(t *testing.T) {
	cases := []struct {
		name string
		args []string
		err  string
	}{
		{
			name: "bundles",
			args: []string{"-b", "b1", "--bundle", "b2"},
		},
		{
			name: "input",
			args: []string{"--input", "some-file"},
		},
		{
			name: "git",
			args: []string{"--git", "git-ref"},
		},
		{
			name: "no bundle, input nor git",
			err:  "at least one of the flags in the group [bundle git input] is required",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbc := trackBundleCmd(nil, nil, nil)
			if err := tbc.ParseFlags(c.args); err != nil {
				t.Error(err)
			}

			err := tbc.ValidateFlagGroups()

			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
