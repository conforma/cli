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

// -------------------------------------------------------------------------------
// This file is almost to identical to the conftest version of this command.
// Use `make conftest-test-cmd-diff` to show a comparison.
// Note also that the way that flags are handled here is not consistent with how
// it's done elsewhere. This intentional in order to be consistent with Conftest.
// -------------------------------------------------------------------------------
package test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const testDesc = `
The 'ec test' command is a thin wrapper for the 'conftest test' command. This
is an experimental feature that requires setting the EC_EXPERIMENTAL environment
variable to "1".

This command tests your configuration files using the Open Policy Agent.

The test command expects one or more input files that will be evaluated
against Open Policy Agent policies. Directories are also supported as valid
inputs.

Policies are written in the Rego language. For more
information on how to write Rego policies, see the documentation:
https://www.openpolicyagent.org/docs/latest/policy-language/
`

const testExample = `
The policy location defaults to the policy directory in the local folder.
The location can be overridden with the '--policy' flag, e.g.:

	$ EC_EXPERIMENTAL=1 ec test --policy <my-directory> <input-file(s)/input-folder>

Some policies are dependant on external data. This data is loaded in separately
from policies. The location of any data directory or file can be specified with
the '--data' flag. If a directory is specified, it will be recursively searched for
any data files. Right now any '.json' or '.yaml' file will be loaded in
and made available in the Rego policies. Data will be made available in Rego based on
the file path where the data was found. For example, if data is stored
under 'policy/exceptions/my_data.yaml', and we execute the following command:

	$ EC_EXPERIMENTAL=1 ec test --data policy <input-file>

The data is available under 'import data.exceptions'.

The test command supports the '--output' flag to specify the type, e.g.:

	$ EC_EXPERIMENTAL=1 ec test -o table -p examples/kubernetes/policy examples/kubernetes/deployment.yaml

Which will return the following output:

	+---------+----------------------------------+--------------------------------+
	| RESULT  |               FILE               |            MESSAGE             |
	+---------+----------------------------------+--------------------------------+
	| success | examples/kubernetes/service.yaml |                                |
	| warning | examples/kubernetes/service.yaml | Found service hello-kubernetes |
	|         |                                  | but services are not allowed   |
	+---------+----------------------------------+--------------------------------+

By default, it will use the regular stdout output. For a full list of available output types, see the of the '--output' flag.

The test command supports the '--update' flag to fetch the latest version of the policy at the given url.
It expects one or more urls to fetch the latest policies from, e.g.:

	$ EC_EXPERIMENTAL=1 ec test --update opa.azurecr.io/test

See the pull command for more details on supported protocols for fetching policies.

When debugging policies it can be useful to use a more verbose policy evaluation output. By using the '--trace' flag
the output will include a detailed trace of how the policy was evaluated, e.g.

	$ EC_EXPERIMENTAL=1 ec test --trace <input-file>
`

const OutputAppstudio = "appstudio"

// newTestCommand creates a new test command.
func newTestCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "test <path> [path [...]]",
		Short:   "Test your configuration files using Open Policy Agent",
		Long:    testDesc,
		Example: testExample,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			flagNames := []string{
				"all-namespaces",
				"combine",
				"data",
				"fail-on-warn",
				"ignore",
				"namespace",
				"no-color",
				"no-fail",
				"suppress-exceptions",
				"file",
				"parser",
				"policy",
				"proto-file-dirs",
				"capabilities",
				"trace",
				"strict",
				"update",
				"junit-hide-message",
				"quiet",
			}
			for _, name := range flagNames {
				if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
					return fmt.Errorf("bind flag: %w", err)
				}
			}

			return nil
		},

		RunE: func(cmd *cobra.Command, fileList []string) error {
			ctx := cmd.Context()

			if len(fileList) < 1 {
				cmd.Usage() //nolint
				return fmt.Errorf("missing required arguments")
			}

			var runner runner.TestRunner

			if err := viper.Unmarshal(&runner); err != nil {
				return fmt.Errorf("unmarshal parameters: %w", err)
			}

			outputFormats, err := cmd.Flags().GetStringSlice("output")
			if err != nil {
				return fmt.Errorf("reading flag: %w", err)
			}
			if len(outputFormats) == 0 {
				outputFormats = []string{output.OutputStandard}
			}

			results, resultsErr := runner.Run(ctx, fileList)
			var exitCode int
			if runner.FailOnWarn {
				exitCode = results.ExitCodeFailOnWarn()
			} else {
				exitCode = results.ExitCode()
			}

			if !runner.Quiet || exitCode != 0 {
				for _, outputAndFormat := range outputFormats {
					parts := strings.SplitN(outputAndFormat, "=", 2)

					format := output.OutputStandard
					outputFilePath := ""
					if len(parts) > 0 {
						format = parts[0]
						if len(parts) == 2 {
							outputFilePath = parts[1]
						}
					}

					if format == OutputAppstudio {
						// The appstudio format is unknown to Conftest so we handle it ourselves

						if resultsErr != nil {
							return appstudioErrorHandler(runner.NoFail, "running test", resultsErr)
						}

						report := appstudioReport(results, runner.Namespace)
						reportOutput, err := json.Marshal(report)
						if err != nil {
							return appstudioErrorHandler(runner.NoFail, "output results", err)
						}

						if outputFilePath != "" {
							err := os.WriteFile(outputFilePath, reportOutput, 0600)
							if err != nil {
								return fmt.Errorf("creating output file: %w", err)
							}
						} else {
							fmt.Fprintln(cmd.OutOrStdout(), string(reportOutput))
						}

					} else {
						// Conftest handles the output

						if resultsErr != nil {
							return fmt.Errorf("running test: %w", resultsErr)
						}

						var outputFile *os.File
						if outputFilePath != "" {
							outputFile, err = os.Create(outputFilePath)
							if err != nil {
								return fmt.Errorf("creating output file %s: %w", outputFilePath, err)
							}
							defer outputFile.Close()
						}

						outputter := output.Get(format, output.Options{
							NoColor:            runner.NoColor,
							SuppressExceptions: runner.SuppressExceptions,
							Tracing:            runner.Trace,
							JUnitHideMessage:   viper.GetBool("junit-hide-message"),
							File:               outputFile,
						})
						if err := outputter.Output(results); err != nil {
							return fmt.Errorf("output results: %w", err)
						}
					}
				}

				// When the no-fail parameter is set, there is no need to figure out the error code
				// as we always want to return zero.
				if runner.NoFail {
					return nil
				}
			}

			os.Exit(exitCode)
			return nil
		},
	}

	cmd.Flags().Bool("fail-on-warn", false, "Return a non-zero exit code if warnings or errors are found")
	cmd.Flags().Bool("no-fail", false, "Return an exit code of zero even if a policy fails")
	cmd.Flags().Bool("no-color", false, "Disable color when printing")
	cmd.Flags().Bool("suppress-exceptions", false, "Do not include exceptions in output")
	cmd.Flags().Bool("all-namespaces", false, "Test policies found in all namespaces")
	cmd.Flags().Bool("quiet", false, "Disable successful test output")

	cmd.Flags().Bool("trace", false, "Enable more verbose trace output for Rego queries")
	cmd.Flags().Bool("strict", false, "Enable strict mode for Rego policies")
	cmd.Flags().Bool("combine", false, "Combine all config files to be evaluated together")

	cmd.Flags().String("ignore", "", "A regex pattern which can be used for ignoring paths")
	cmd.Flags().String("parser", "", fmt.Sprintf("Parser to use to parse the configurations. Valid parsers: %s", parser.Parsers()))
	cmd.Flags().String("capabilities", "", "Path to JSON file that can restrict opa functionality against a given policy. Default: all operations allowed")

	cmd.Flags().String("file", "", "File path to write output to")
	cmd.Flags().Bool("junit-hide-message", false, "Do not include the violation message in the JUnit test name")

	cmd.Flags().StringSliceP("policy", "p", []string{"policy"}, "Path to the Rego policy files directory")
	cmd.Flags().StringSliceP("update", "u", []string{}, "A list of URLs can be provided to the update flag, which will download before the tests run")
	cmd.Flags().StringSliceP("namespace", "n", []string{"main"}, "Test policies in a specific namespace")
	cmd.Flags().StringSliceP("data", "d", []string{}, "A list of paths from which data for the rego policies will be recursively loaded")
	cmd.Flags().StringSliceP("output", "o", []string{}, fmt.Sprintf("Output format for conftest results - valid options are: %s. You can optionally specify a file for the output, e.g. -o json=out.json", append(output.Outputs(), OutputAppstudio)))

	cmd.Flags().StringSlice("proto-file-dirs", []string{}, "A list of directories containing Protocol Buffer definitions")

	return &cmd
}

var TestCmd *cobra.Command

func init() {
	TestCmd = newTestCommand()
}
