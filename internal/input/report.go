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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package input

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/version"
)

type Input struct {
	FilePath     string             `json:"filepath"`
	Violations   []evaluator.Result `json:"violations"`
	Warnings     []evaluator.Result `json:"warnings"`
	Successes    []evaluator.Result `json:"successes"`
	Success      bool               `json:"success"`
	SuccessCount int                `json:"success-count"`
}

type Report struct {
	Success       bool `json:"success"`
	created       time.Time
	FilePaths     []Input                          `json:"filepaths"`
	Policy        ecc.EnterpriseContractPolicySpec `json:"policy"`
	EcVersion     string                           `json:"ec-version"`
	Data          any                              `json:"-"`
	EffectiveTime time.Time                        `json:"effective-time"`
	PolicyInput   [][]byte                         `json:"-"`
	ShowSuccesses bool                             `json:"-"`
	ShowWarnings  bool                             `json:"-"`
}

type summary struct {
	FilePaths []inputSummary `json:"filepaths"`
	Success   bool           `json:"success"`
	Key       string         `json:"key"`
}

type inputSummary struct {
	FilePath        string              `json:"name"`
	Success         bool                `json:"success"`
	Violations      map[string][]string `json:"violations"`
	Warnings        map[string][]string `json:"warnings"`
	Successes       map[string][]string `json:"successes"`
	TotalViolations int                 `json:"total_violations"`
	TotalWarnings   int                 `json:"total_warnings"`
	TotalSuccesses  int                 `json:"total_successes"`
}

// TestReport represents the standardized TEST_OUTPUT format.
// The `Namespace` attribute is required for the appstudio results API. However,
// it is always an empty string from the cli as a way to indicate all
// namespaces were used.
type TestReport struct {
	Timestamp string `json:"timestamp"`
	Namespace string `json:"namespace"`
	Successes int    `json:"successes"`
	Failures  int    `json:"failures"`
	Warnings  int    `json:"warnings"`
	Result    string `json:"result"`
	Note      string `json:"note,omitempty"`
}

// Possible formats the report can be written as.
const (
	JSON    = "json"
	YAML    = "yaml"
	Text    = "text"
	Summary = "summary"
)

// WriteReport returns a new instance of Report representing the state of
// the filepaths provided.
func NewReport(inputs []Input, policy policy.Policy, policyInput [][]byte, showSuccesses bool, showWarnings bool) (Report, error) {
	success := true

	// Set the report success, remains true if all the files were successfully validated
	for _, fpath := range inputs {
		if !fpath.Success {
			success = false
			break
		}
	}

	info, _ := version.ComputeInfo()

	return Report{
		Success:       success,
		created:       time.Now().UTC(),
		FilePaths:     inputs,
		Policy:        policy.Spec(),
		EcVersion:     info.Version,
		EffectiveTime: policy.EffectiveTime().UTC(),
		PolicyInput:   policyInput,
		ShowSuccesses: showSuccesses,
		ShowWarnings:  showWarnings,
	}, nil
}

// WriteAll writes the report to all the given targets.
func (r Report) WriteAll(targets []string, p format.TargetParser) (allErrors error) {
	if len(targets) == 0 {
		targets = append(targets, Text)
	}
	for _, targetName := range targets {
		target, err := p.Parse(targetName)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		data, err := r.toFormat(target.Format)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if !bytes.HasSuffix(data, []byte{'\n'}) {
			data = append(data, "\n"...)
		}

		if _, err := target.Write(data); err != nil {
			allErrors = errors.Join(allErrors, err)
		}
	}
	return
}

// toFormat converts the report into the given format.
func (r *Report) toFormat(format string) (data []byte, err error) {
	switch format {
	case JSON:
		data, err = json.Marshal(r)
	case YAML:
		data, err = yaml.Marshal(r)
	case Text:
		data, err = generateTextReport(r)
	case Summary:
		data, err = json.Marshal(r.toSummary())
	default:
		return nil, fmt.Errorf("%q is not a valid report format", format)
	}
	return
}

// toSummary returns a condensed version of the report.
func (r *Report) toSummary() summary {
	pr := summary{}
	for _, cmp := range r.FilePaths {
		c := inputSummary{
			FilePath:        cmp.FilePath,
			TotalViolations: len(cmp.Violations),
			TotalWarnings:   len(cmp.Warnings),

			// Because cmp.Successes does not get populated unless the --show-successes
			// flag was set, cmp.SuccessCount is used here instead of len(cmp.Successes)
			TotalSuccesses: cmp.SuccessCount,

			Success:    cmp.Success,
			Violations: condensedMsg(cmp.Violations),
			Warnings:   condensedMsg(cmp.Warnings),
			Successes:  condensedMsg(cmp.Successes),
		}
		pr.FilePaths = append(pr.FilePaths, c)
	}
	return pr
}

// condensedMsg reduces repetitive error messages.
func condensedMsg(results []evaluator.Result) map[string][]string {
	maxErr := 1
	shortNames := make(map[string][]string)
	count := make(map[string]int)
	for _, v := range results {
		code, isPresent := v.Metadata["code"]
		// we don't want to keep count of the empty string
		if isPresent {
			code := fmt.Sprintf("%v", code)
			if count[code] < maxErr {
				shortNames[code] = append(shortNames[code], v.Message)
			}
			count[code] = count[code] + 1
		}
	}
	for k := range shortNames {
		if count[k] > maxErr {
			shortNames[k] = append(shortNames[k], fmt.Sprintf("There are %v more %q messages", count[k]-1, k))
		}
	}
	return shortNames
}

//go:embed templates/*.tmpl
var efs embed.FS

func generateTextReport(r *Report) ([]byte, error) {
	// Prepare some template input
	// Calculate totals for the test report structure
	var successes, failures, warnings int
	for _, input := range r.FilePaths {
		successes += input.SuccessCount
		failures += len(input.Violations)
		warnings += len(input.Warnings)
	}

	result := "SUCCESS"
	if failures > 0 {
		result = "FAILURE"
	} else if warnings > 0 {
		result = "WARNING"
	}

	testReport := TestReport{
		Timestamp: r.created.Format(time.RFC3339),
		Namespace: "",
		Successes: successes,
		Failures:  failures,
		Warnings:  warnings,
		Result:    result,
	}

	input := struct {
		Report     *Report
		TestReport TestReport
	}{
		Report:     r,
		TestReport: testReport,
	}

	return utils.RenderFromTemplatesWithMain(input, "text_report.tmpl", efs)
}
