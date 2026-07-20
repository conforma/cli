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
	"slices"
	"sort"
	"strings"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/input"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/server"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
)

type InputValidationFunc func(context.Context, string, policy.Policy, bool) (*output.Output, error)

func validateInputCmd(validate InputValidationFunc) *cobra.Command {
	data := struct {
		effectiveTime       string
		filePaths           []string
		forceColor          bool
		info                bool
		namespaces          []string
		noColor             bool
		output              []string
		policy              policy.Policy
		policyConfiguration string
		strict              bool
		workers             int
		serverMode          bool
		serverAddress       string
		serverPort          int
	}{
		strict:        true,
		workers:       5,
		serverAddress: "127.0.0.1",
		serverPort:    8080,
	}
	cmd := &cobra.Command{
		Use:   "input [file ...] [flags]",
		Short: "Validate arbitrary JSON or yaml file input conformance with the provided policies",
		Long: fmt.Sprintf(hd.Doc(`
			Validate conformance of arbitrary JSON or yaml file input with the provided policies

			For each file, validation is performed to determine if the file conforms to rego policies
			defined in the EnterpriseContractPolicy.

			Input files can be specified as positional arguments or via the --file flag (deprecated).
			If both are provided, the values are combined.

			When --server is provided, a persistent HTTP server is started instead of running a one-shot
			evaluation. Policies are loaded once at startup. The server exposes the following endpoints:

			  POST /v1/validate/input  - Evaluate input (JSON or YAML body)
			  GET  /live               - Liveness probe (always 200)
			  GET  /ready              - Readiness probe (200 when policies are loaded)

			The evaluation endpoint returns the same JSON structure as --output json. HTTP 200 is returned
			for all completed evaluations (the "success" field distinguishes pass/fail). Restart the server
			to pick up policy changes.

			Error responses use HTTP 400 (bad request), 413 (body too large), or 500 (internal error) with
			a JSON body: {"error":"<message>","status":<code>}.

			Server limits: request body max %dMB, evaluation timeout %ds.
			`), server.MaxRequestBodySize>>20, server.EvaluationTimeout/time.Second),
		Example: hd.Doc(`
			Validate a single file using positional arguments
			ec validate input /path/to/file.json --policy my-policy.yaml

			Validate multiple files using positional arguments
			ec validate input /path/to/file.yaml /path/to/file2.yaml --policy my-policy.yaml

			Validate all YAML files in a directory using shell glob expansion
			ec validate input *.yaml --policy my-policy.yaml

			Use the deprecated --file flag (still functional, multiple forms supported)
			ec validate input --file /path/to/file.json --policy my-policy.yaml
			ec validate input --file /path/to/file.yaml --file /path/to/file2.yaml --policy my-policy.yaml
			ec validate input --file="/path/to/file.json,/path/to/file2.json" --policy my-policy.yaml

			Use a git url for the policy configuration. In the first example there should be a '.ec/policy.yaml'
			or a 'policy.yaml' inside a directory called 'default' in the top level of the git repo. In the second
			example there should be a '.ec/policy.yaml' or a 'policy.yaml' file in the top level
			of the git repo. For git repos not hosted on 'github.com' or 'gitlab.com', prefix the url with
			'git::'. For the policy configuration files you can use json instead of yaml if you prefer.

			  ec validate input /path/to/file.json --policy github.com/user/repo//default?ref=main

			  ec validate input /path/to/file.yaml --policy github.com/user/repo

			Start a persistent HTTP server for policy evaluation over REST:

			  ec validate input --server --policy my-policy.yaml

			Send a request to the evaluation endpoint:

			  curl -s -X POST -H 'Content-Type: application/json' --data-binary @input.json http://localhost:8080/v1/validate/input

			  curl -s -X POST -H 'Content-Type: application/yaml' --data-binary @input.yaml http://localhost:8080/v1/validate/input

			Start the server on a custom port:

			  ec validate input --server --server-port 9090 --policy my-policy.yaml
`),
		PreRunE: func(cmd *cobra.Command, args []string) (allErrors error) {
			// Merge positional arguments into filePaths
			data.filePaths = append(data.filePaths, args...)

			// Deduplicate file paths
			seen := make(map[string]struct{}, len(data.filePaths))
			unique := make([]string, 0, len(data.filePaths))
			for _, f := range data.filePaths {
				if _, ok := seen[f]; !ok {
					seen[f] = struct{}{}
					unique = append(unique, f)
				}
			}
			data.filePaths = unique

			// Strip empty and whitespace-only entries
			data.filePaths = slices.DeleteFunc(data.filePaths, func(s string) bool {
				return strings.TrimSpace(s) == ""
			})

			if data.serverMode && len(data.filePaths) > 0 {
				allErrors = errors.Join(allErrors, fmt.Errorf("--server and input files are mutually exclusive"))
				return
			}
			if !data.serverMode && len(data.filePaths) == 0 {
				allErrors = errors.Join(allErrors, fmt.Errorf("at least one input file must be specified as a positional argument or via the --file flag"))
				return
			}

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
			if data.serverMode {
				ignoredInServerMode := []string{"output", "strict", "workers", "no-color", "color"}
				for _, name := range ignoredInServerMode {
					if cmd.Flags().Changed(name) {
						log.Warnf("Flag --%s has no effect in server mode", name)
					}
				}

				showSuccesses, _ := cmd.Flags().GetBool("show-successes")
				showWarnings, _ := cmd.Flags().GetBool("show-warnings")
				showPolicyDocsLink, _ := cmd.Flags().GetBool("show-policy-docs-link")

				srv := server.New(server.Config{
					Address:            data.serverAddress,
					Port:               data.serverPort,
					Policy:             data.policy,
					Info:               data.info,
					ShowSuccesses:      showSuccesses,
					ShowWarnings:       showWarnings,
					ShowPolicyDocsLink: showPolicyDocsLink,
				})
				return srv.Start(cmd.Context())
			}

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
			showPolicyDocsLink, _ := cmd.Flags().GetBool("show-policy-docs-link")

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

			report, err := input.NewReport(inputs, data.policy, manyPolicyInput, showSuccesses, showWarnings, showPolicyDocsLink)
			if err != nil {
				return err
			}

			utils.SetColorEnabled(data.noColor, data.forceColor)

			p := format.NewTargetParser(input.Text, format.Options{ShowSuccesses: showSuccesses, ShowWarnings: showWarnings, ShowPolicyDocsLink: showPolicyDocsLink}, cmd.OutOrStdout(), utils.FS(cmd.Context()))
			if err := report.WriteAll(data.output, p); err != nil {
				return err
			}

			if data.strict && !report.Success {
				return errors.New("success criteria not met")
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&data.filePaths, "file", "f", data.filePaths, "DEPRECATED: use positional arguments instead. Path to input YAML/JSON file")

	cmd.Flags().StringVarP(&data.policyConfiguration, "policy", "p", data.policyConfiguration, hd.Doc(`
		Policy configuration as:
		* file (policy.yaml)
		* git reference (github.com/user/repo//default?ref=main), or
		* inline JSON ('{sources: {...}}')")`))

	validOutputFormats := []string{input.JSON, input.YAML, input.Text, input.Summary}
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

	cmd.Flags().BoolVar(&data.noColor, "no-color", false, hd.Doc(`
		Disable color when using text output even when the current terminal supports it`))

	cmd.Flags().BoolVar(&data.forceColor, "color", false, hd.Doc(`
		Enable color when using text output even when the current terminal does not support it`))

	if err := cmd.Flags().MarkHidden("file"); err != nil {
		panic(err)
	}

	cmd.Flags().BoolVar(&data.serverMode, "server", false, hd.Doc(`
		Start a persistent HTTP server instead of running a one-shot evaluation.
		Mutually exclusive with input files. Policies are loaded once at startup.
		Note: the server has no built-in authentication or rate limiting.
		Use a reverse proxy or network policy to restrict access in production.`))

	cmd.Flags().StringVar(&data.serverAddress, "server-address", data.serverAddress, hd.Doc(`
		Address for the HTTP server to bind to when running in server mode.
		Defaults to 127.0.0.1 (localhost only). Set to 0.0.0.0 to listen
		on all interfaces.`))

	cmd.Flags().IntVar(&data.serverPort, "server-port", data.serverPort, hd.Doc(`
		Port for the HTTP server when running in server mode.`))

	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}

	return cmd
}
