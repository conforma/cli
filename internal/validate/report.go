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
	"errors"
	"sort"
	"strings"

	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
)

// Result represents the result of validating a single component
type Result struct {
	Err         error
	Component   applicationsnapshot.Component
	PolicyInput []byte
}

// PopulateResultFromOutput decomposes an output.Output object into a Result object.
// This is used to convert validation output into a consistent result structure
// that can be used for report generation.
func PopulateResultFromOutput(
	out *output.Output,
	err error,
	comp app.SnapshotComponent,
	showSuccesses bool,
	outputFormats []string,
) Result {
	res := Result{
		Err: err,
		Component: applicationsnapshot.Component{
			SnapshotComponent: comp,
			Success:           err == nil,
		},
	}

	// Only populate from output if there's no error and output exists
	if err == nil {
		if out != nil {
			// Normal validation completed
			res.Component.Violations = out.Violations()
			res.Component.Warnings = out.Warnings()

			successes := out.Successes()
			res.Component.SuccessCount = len(successes)
			if showSuccesses {
				res.Component.Successes = successes
			}

			res.Component.Signatures = out.Signatures
			// Create a new result object for attestations. The point is to only keep the data that's needed.
			// For example, the Statement is only needed when the full attestation is printed.
			for _, att := range out.Attestations {
				attResult := applicationsnapshot.NewAttestationResult(att)
				if ContainsOutputFormat(outputFormats, "attestation") {
					attResult.Statement = att.Statement()
				}
				res.Component.Attestations = append(res.Component.Attestations, attResult)
			}
			res.Component.ContainerImage = out.ImageURL
			res.PolicyInput = out.PolicyInput
		} else {
			// Validation was skipped due to valid VSA - no violations, no processing needed
			res.Component.ContainerImage = comp.ContainerImage
		}
	}
	res.Component.Success = err == nil && len(res.Component.Violations) == 0

	return res
}

// ContainsOutputFormat checks if the specified output format is in the output formats list.
// It handles formats that may include file paths (e.g., "attestation=/path/to/file").
func ContainsOutputFormat(outputFormats []string, format string) bool {
	for _, item := range outputFormats {
		parts := strings.Split(item, "=")
		if parts[0] == format {
			return true
		}
	}
	return false
}

// CollectComponentResults processes a slice of results, accumulating errors and collecting successful components.
// It returns the collected components (sorted by ContainerImage), policy inputs, and any aggregated errors.
// The errorFormatter is called for each failed result to create an error message.
func CollectComponentResults(
	results []Result,
	errorFormatter func(Result) error,
) ([]applicationsnapshot.Component, [][]byte, error) {
	var components []applicationsnapshot.Component
	var manyPolicyInput [][]byte
	var allErrors error

	for _, r := range results {
		if r.Err != nil {
			e := errorFormatter(r)
			allErrors = errors.Join(allErrors, e)
		} else {
			components = append(components, r.Component)
			manyPolicyInput = append(manyPolicyInput, r.PolicyInput)
		}
	}

	if allErrors != nil {
		return nil, nil, allErrors
	}

	// Ensure some consistency in output by sorting components by ContainerImage
	sort.Slice(components, func(i, j int) bool {
		return components[i].ContainerImage > components[j].ContainerImage
	})

	return components, manyPolicyInput, nil
}

// ReportData contains the data needed to create an application snapshot report
type ReportData struct {
	Snapshot           string
	Components         []applicationsnapshot.Component
	Policy             policy.Policy
	PolicyInputs       [][]byte
	Expansion          *applicationsnapshot.ExpansionInfo
	ShowSuccesses      bool
	ShowWarnings       bool
	ShowPolicyDocsLink bool
}

// ReportOutputOptions contains options for formatting and writing the report
type ReportOutputOptions struct {
	Output     []string
	NoColor    bool
	ForceColor bool
}

// WriteReport creates and writes a report using the provided data and options.
// It returns the created report so it can be used for further processing (e.g., VSA validation).
func WriteReport(data ReportData, opts ReportOutputOptions, cmd *cobra.Command) (applicationsnapshot.Report, error) {
	report, err := applicationsnapshot.NewReport(
		data.Snapshot,
		data.Components,
		data.Policy,
		data.PolicyInputs,
		data.ShowSuccesses,
		data.ShowWarnings,
		data.ShowPolicyDocsLink,
		data.Expansion,
	)
	if err != nil {
		return applicationsnapshot.Report{}, err
	}

	formatOpts := format.Options{
		ShowSuccesses:      data.ShowSuccesses,
		ShowWarnings:       data.ShowWarnings,
		ShowPolicyDocsLink: data.ShowPolicyDocsLink,
	}
	p := format.NewTargetParser(
		applicationsnapshot.JSON,
		formatOpts,
		cmd.OutOrStdout(),
		utils.FS(cmd.Context()),
	)
	utils.SetColorEnabled(opts.NoColor, opts.ForceColor)

	if err := report.WriteAll(opts.Output, p); err != nil {
		return applicationsnapshot.Report{}, err
	}
	return report, nil
}

// ProcessOutputForImageValidation processes an output.Output using the same pipeline
// as the validate image command. This ensures consistent processing for both
// validate image and validate vsa (fallback) commands.
// Returns the processed Component which contains violations, warnings, successes
// processed with the same logic (filtering, sorting, etc.) as the validate image command.
func ProcessOutputForImageValidation(
	out *output.Output,
	err error,
	comp app.SnapshotComponent,
	showSuccesses bool,
	outputFormats []string,
) applicationsnapshot.Component {
	// Use the same processing pipeline as validate image command
	result := PopulateResultFromOutput(out, err, comp, showSuccesses, outputFormats)
	return result.Component
}
