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
// This file is "almost" identical to the conftest version of this command.
// Use `make conftest-test-cmd-diff` to show a comparison.
// Note also that the way that flags are handled here is not consistent with how
// it's done elsewhere. This intentional in order to be consistent with Conftest.
// -------------------------------------------------------------------------------
package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
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
the output will include a detailed trace of how the policy was evaluated. The trace output will be written to stderr,
while the regular output will be written to stdout. This allows you to use the '--trace' flag together with any output
format, including table, JSON, etc.

	# Trace output
	$ EC_EXPERIMENTAL=1 ec test --trace <input-file>

	# Trace output with any non-standard output format
	$ EC_EXPERIMENTAL=1 ec test --trace --output=table <input-file>

	# Redirect trace output to a file while viewing formatted output
	$ EC_EXPERIMENTAL=1 ec test --trace --output=json <input-file> 2>trace.log
`

// TestRun stores the compiler and store for a test run.
type TestRun struct {
	Compiler *ast.Compiler
	Store    storage.Store
}

const OutputAppstudio = "appstudio"

// NewTestCommand creates a new test command.
func NewTestCommand(ctx context.Context) *cobra.Command {
	cmd := cobra.Command{
		Use:   "test <path> [path [...]]",
		Short: "Test your configuration files using Open Policy Agent",
		Long:  testDesc,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
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
				"output",
				"parser",
				"policy",
				"proto-file-dirs",
				"capabilities",
				"rego-version",
				"trace",
				"strict",
				"show-builtin-errors",
				"update",
				"junit-hide-message",
				"quiet",
				"tls",
			}
			for _, name := range flagNames {
				if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
					return fmt.Errorf("bind flag: %w", err)
				}
			}

			return nil
		},

		RunE: func(cmd *cobra.Command, fileList []string) error {
			if len(fileList) < 1 {
				cmd.Usage() //nolint
				return fmt.Errorf("missing required arguments")
			}

			var runner runner.TestRunner
			if err := viper.Unmarshal(&runner); err != nil {
				return fmt.Errorf("unmarshal parameters: %w", err)
			}

			results, resultsErr := runner.Run(ctx, fileList)

			exitCode := results.ExitCode()
			if runner.FailOnWarn {
				exitCode = results.ExitCodeFailOnWarn()
			}

			// Do this so we can write the appstudio format to a file
			// with the `--output appstudio=file.json` style flag
			format := runner.Output
			parts := strings.SplitN(format, "=", 2)
			outputFilePath := ""
			if len(parts) > 0 {
				format = parts[0]
				if len(parts) == 2 {
					outputFilePath = parts[1]
				}
			}

			if !runner.Quiet || exitCode != 0 {
				if err := handleOutput(cmd, &runner, format, outputFilePath, results, resultsErr); err != nil {
					return err
				}
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
	cmd.Flags().Bool("show-builtin-errors", false, "Collect and return all encountered built-in errors")
	cmd.Flags().Bool("combine", false, "Combine all config files to be evaluated together")

	cmd.Flags().String("ignore", "", "A regex pattern which can be used for ignoring paths")
	cmd.Flags().String("parser", "", fmt.Sprintf("Parser to use to parse the configurations. Valid parsers: %s", parser.Parsers()))
	cmd.Flags().String("capabilities", "", "Path to JSON file that can restrict opa functionality against a given policy. Default: all operations allowed")
	cmd.Flags().String("rego-version", "v1", "Which version of Rego syntax to use. Options: v0, v1")

	cmd.Flags().StringP("output", "o", output.OutputStandard, fmt.Sprintf("Output format for conftest results - valid options are: %s", output.Outputs()))
	cmd.Flags().Bool("junit-hide-message", false, "Do not include the violation message in the JUnit test name")

	cmd.Flags().StringSliceP("policy", "p", []string{"policy"}, "Path to the Rego policy files directory")
	cmd.Flags().StringSliceP("update", "u", []string{}, "A list of URLs can be provided to the update flag, which will download before the tests run")
	cmd.Flags().StringSliceP("namespace", "n", []string{"main"}, "Test policies in a specific namespace")
	cmd.Flags().StringSliceP("data", "d", []string{}, "A list of paths from which data for the rego policies will be recursively loaded")

	cmd.Flags().StringSlice("proto-file-dirs", []string{}, "A list of directories containing Protocol Buffer definitions")
	cmd.Flags().Bool("tls", true, "Use TLS to access the registry")

	return &cmd
}

// handleOutput handles output formatting for test results
func handleOutput(cmd *cobra.Command, r *runner.TestRunner, format, outputFilePath string, results output.CheckResults, resultsErr error) error {
	if format == OutputAppstudio {
		return handleAppstudioOutput(cmd, r, outputFilePath, results, resultsErr)
	}
	return handleConftestOutput(r, results, resultsErr)
}

// handleAppstudioOutput handles appstudio format output
func handleAppstudioOutput(cmd *cobra.Command, r *runner.TestRunner, outputFilePath string, results output.CheckResults, resultsErr error) error {
	if resultsErr != nil {
		return appstudioErrorHandler(r.NoFail, "running test", resultsErr)
	}

	report := appstudioReport(results, r.Namespace)
	reportOutput, err := json.Marshal(report)
	if err != nil {
		return appstudioErrorHandler(r.NoFail, "output results", err)
	}

	if outputFilePath == "" {
		fmt.Fprintln(cmd.OutOrStdout(), string(reportOutput))
		return nil
	}

	if err := os.WriteFile(outputFilePath, reportOutput, 0600); err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	return nil
}

// handleConftestOutput handles conftest format output
func handleConftestOutput(r *runner.TestRunner, results output.CheckResults, resultsErr error) error {
	if resultsErr != nil {
		return fmt.Errorf("running test: %w", resultsErr)
	}

	outputter := output.Get(r.Output, output.Options{
		NoColor:            r.NoColor,
		SuppressExceptions: r.SuppressExceptions,
		Tracing:            r.Trace,
		JUnitHideMessage:   viper.GetBool("junit-hide-message"),
	})
	if err := outputter.Output(results); err != nil {
		return fmt.Errorf("output results: %w", err)
	}
	return nil
}
