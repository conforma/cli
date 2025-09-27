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

package validate

import (
	"context"
	"errors"
	"fmt"
	"runtime/trace"
	"sort"
	"strings"

	hd "github.com/MakeNowJust/heredoc/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/input"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
)

type InputValidationFunc func(context.Context, string, policy.Policy, bool) (*output.Output, error)

func validateInputCmd(validate InputValidationFunc) *cobra.Command {
	data := struct {
		effectiveTime       string
		filePaths           []string
		filterType          string
		info                bool
		namespaces          []string
		output              []string
		policy              policy.Policy
		policyConfiguration string
		strict              bool
		workers             int
	}{
		strict:     true,
		workers:    5,
		filterType: "include-exclude", // Default to include-exclude filter
	}
	cmd := &cobra.Command{
		Use:   "input",
		Short: "Validate arbitrary JSON or yaml file input conformance with the provided policies",
		Long: hd.Doc(`
			Validate conformance of arbitrary JSON or yaml file input with the provided policies

			For each file, validation is performed to determine if the file conforms to rego policies
			defined in the EnterpriseContractPolicy.
			`),
		Example: hd.Doc(`
			Use an EnterpriseContractPolicy spec from a local YAML file to validate a single file
			ec validate input --file /path/to/file.json --policy my-policy.yaml

			Use an EnterpriseContractPolicy spec from a local YAML file to validate multiple files
			The file flag can be repeated for multiple input files.
			ec validate input --file /path/to/file.yaml --file /path/to/file2.yaml --policy my-policy.yaml

			Use an EnterpriseContractPolicy spec from a local YAML file to validate multiple files
			The file flag can take a comma separated series of files.
			ec validate input --file="/path/to/file.json,/path/to/file2.json" --policy my-policy.yaml

			Use a git url for the policy configuration. In the first example there should be a '.ec/policy.yaml'
			or a 'policy.yaml' inside a directory called 'default' in the top level of the git repo. In the second
			example there should be a '.ec/policy.yaml' or a 'policy.yaml' file in the top level
			of the git repo. For git repos not hosted on 'github.com' or 'gitlab.com', prefix the url with
			'git::'. For the policy configuration files you can use json instead of yaml if you prefer.

			  ec validate input --file /path/to/file.json --policy github.com/user/repo//default?ref=main

			  ec validate input --file /path/to/file.yaml --policy github.com/user/repo

`),
		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			ctx := cmd.Context()

			policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfiguration)
			if err != nil {
				allErrors = errors.Join(allErrors, err)
				return
			}
			data.policyConfiguration = policyConfiguration

			if p, err := policy.NewInputPolicy(cmd.Context(), data.policyConfiguration, data.effectiveTime); err != nil {
				allErrors = errors.Join(allErrors, err)
			} else {
				data.policy = p
			}
			return
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if trace.IsEnabled() {
				ctx, task := trace.NewTask(cmd.Context(), "ec:validate-inputs")
				cmd.SetContext(ctx)
				defer task.End()
			}

			type result struct {
				err         error
				input       input.Input
				policyInput []byte
			}

			showSuccesses, _ := cmd.Flags().GetBool("show-successes")
			showWarnings, _ := cmd.Flags().GetBool("show-warnings")

			// Set numWorkers to the value from our flag. The default is 5.
			numWorkers := data.workers

			jobs := make(chan string, len(data.filePaths))
			results := make(chan result, len(data.filePaths))

			// worker function processes one file path at a time.
			worker := func(id int, jobs <-chan string, results chan<- result) {
				log.Debugf("Starting worker %d", id)
				for fpath := range jobs {
					ctx := cmd.Context()
					var task *trace.Task
					if trace.IsEnabled() {
						ctx, task = trace.NewTask(ctx, "ec:validate-input")
						trace.Logf(ctx, "", "workerID=%d, file=%s", id, fpath)
					}

					out, err := validate(ctx, fpath, data.policy, data.info)
					res := result{
						err: err,
						input: input.Input{
							FilePath: fpath,
							Success:  err == nil,
						},
					}

					if err == nil {
						res.input.Violations = out.Violations()

						warnings := out.Warnings()
						if showWarnings {
							res.input.Warnings = warnings
						}

						successes := out.Successes()
						res.input.SuccessCount = len(successes)
						if showSuccesses {
							res.input.Successes = successes
						}
						res.input.Success = (len(res.input.Violations) == 0)
						res.policyInput = out.PolicyInput
					}

					if task != nil {
						task.End()
					}
					results <- res
				}
				log.Debugf("Done with worker %d", id)
			}

			// Start the worker pool
			for i := 0; i < numWorkers; i++ {
				go worker(i, jobs, results)
			}

			// Push all jobs (file paths) to the jobs channel
			for _, f := range data.filePaths {
				jobs <- f
			}
			close(jobs)

			var inputs []input.Input
			var manyPolicyInput [][]byte
			var allErrors error = nil

			// Collect all results
			for i := 0; i < len(data.filePaths); i++ {
				r := <-results
				if r.err != nil {
					e := fmt.Errorf("error validating file %s: %w", r.input.FilePath, r.err)
					allErrors = errors.Join(allErrors, e)
				} else {
					inputs = append(inputs, r.input)
					manyPolicyInput = append(manyPolicyInput, r.policyInput)
				}
			}
			close(results)

			if allErrors != nil {
				return allErrors
			}

			// Sort inputs for consistent output
			sort.Slice(inputs, func(i, j int) bool {
				return inputs[i].FilePath > inputs[j].FilePath
			})

			report, err := input.NewReport(inputs, data.policy, manyPolicyInput)
			if err != nil {
				return err
			}

			p := format.NewTargetParser(input.JSON, format.Options{ShowSuccesses: showSuccesses, ShowWarnings: showWarnings}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
			if err := report.WriteAll(data.output, p); err != nil {
				return err
			}

			if data.strict && !report.Success {
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&data.filePaths, "file", "f", data.filePaths, "path to input YAML/JSON file (required)")

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
		Policy configuration as:
		* file (policy.yaml)
		* git reference (github.com/user/repo//default?ref=main), or
		* inline JSON ('{sources: {...}}')")`))

	validOutputFormats := applicationsnapshot.OutputFormats
	cmd.Flags().StringSliceVarP(&data.output, "output", "o", data.output, hd.Doc(`
		Write output to a file in a specific format, e.g. yaml=/tmp/output.yaml. Use empty string
		path for stdout, e.g. yaml. May be used multiple times. Possible formats are:
		`+strings.Join(validOutputFormats, ", ")+`. In following format and file path
		additional options can be provided in key=value form following the question
		mark (?) sign, for example: --output text=output.txt?show-successes=false
	`))

	cmd.Flags().BoolVarP(&data.strict, "strict", "s", data.strict,
		"Return non-zero status on non-successful validation")

	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", policy.Now, hd.Doc(`
		Run policy checks with the provided time. Useful for testing rules with
		effective dates in the future. The value can be "now" (default) - for
		current time, or a RFC3339 formatted value, e.g. 2022-11-18T00:00:00Z.`))

	cmd.Flags().BoolVar(&data.info, "info", data.info, hd.Doc(`
		Include additional information on the failures. For instance for policy
		violations, include the title and the description of the failed policy
		rule.`))

	cmd.Flags().IntVar(&data.workers, "workers", data.workers, hd.Doc(`
		Number of workers to use for validation. Defaults to 5.`))

	cmd.Flags().StringVar(&data.filterType, "filter-type", data.filterType, hd.Doc(`
		Filter type to use for policy evaluation. Options: "include-exclude" (default) or "ec-policy".
		- "include-exclude": Uses traditional include/exclude filtering without pipeline intentions
		- "ec-policy": Uses Enterprise Contract policy filtering with pipeline intention support`))

	if err := cmd.MarkFlagRequired("file"); err != nil {
		panic(err)
	}

	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}

	return cmd
}
