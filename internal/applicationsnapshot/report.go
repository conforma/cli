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

package applicationsnapshot

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/signature"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/version"
)

type Component struct {
	app.SnapshotComponent
	Violations   []evaluator.Result          `json:"violations,omitempty"`
	Warnings     []evaluator.Result          `json:"warnings,omitempty"`
	Successes    []evaluator.Result          `json:"successes,omitempty"`
	Success      bool                        `json:"success"`
	SuccessCount int                         `json:"-"`
	Signatures   []signature.EntitySignature `json:"signatures,omitempty"`
	Attestations []AttestationResult         `json:"attestations,omitempty"`
}

type Report struct {
	Success       bool `json:"success"`
	created       time.Time
	Snapshot      string                           `json:"snapshot,omitempty"`
	Components    []Component                      `json:"components"`
	Key           string                           `json:"key"`
	Policy        ecc.EnterpriseContractPolicySpec `json:"policy"`
	EcVersion     string                           `json:"ec-version"`
	Data          any                              `json:"-"`
	EffectiveTime time.Time                        `json:"effective-time"`
	PolicyInput   [][]byte                         `json:"-"`
	ShowSuccesses bool                             `json:"-"`
}

type summary struct {
	Snapshot   string             `json:"snapshot,omitempty"`
	Components []componentSummary `json:"components"`
	Success    bool               `json:"success"`
	Key        string             `json:"key"`
}

type componentSummary struct {
	Name            string              `json:"name"`
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
	JSON            = "json"
	YAML            = "yaml"
	Text            = "text"
	AppStudio       = "appstudio"
	Summary         = "summary"
	SummaryMarkdown = "summary-markdown"
	JUnit           = "junit"
	Attestation     = "attestation"
	PolicyInput     = "policy-input"
	VSA             = "vsa"
	// Deprecated old version of appstudio. Remove some day.
	HACBS = "hacbs"
)

var OutputFormats = []string{
	JSON,
	YAML,
	Text,
	AppStudio,
	Summary,
	SummaryMarkdown,
	JUnit,
	Attestation,
	PolicyInput,
	VSA,
}

// WriteReport returns a new instance of Report representing the state of
// components from the snapshot.
func NewReport(snapshot string, components []Component, policy policy.Policy, policyInput [][]byte, showSuccesses bool) (Report, error) {
	success := true

	// Set the report success, remains true if all components are successful
	for _, component := range components {
		if !component.Success {
			success = false
			break
		}
	}

	key, err := policy.PublicKeyPEM()
	if err != nil {
		return Report{}, err
	}

	// TODO: Add some keyless information to the report.

	info, _ := version.ComputeInfo()

	return Report{
		Snapshot:      snapshot,
		Success:       success,
		Components:    components,
		created:       time.Now().UTC(),
		Key:           string(key),
		Policy:        policy.Spec(),
		EcVersion:     info.Version,
		PolicyInput:   policyInput,
		EffectiveTime: policy.EffectiveTime().UTC(),
		ShowSuccesses: showSuccesses,
	}, nil
}

// WriteAll writes the report to all the given targets.
func (r Report) WriteAll(targets []string, p format.TargetParser) (allErrors error) {
	log.Debugf("DEBUG: WriteAll called with %d targets: %v", len(targets), targets)
	if len(targets) == 0 {
		targets = append(targets, Text)
	}
	for _, targetName := range targets {
		log.Debugf("DEBUG: Processing target: %s", targetName)
		target, err := p.Parse(targetName)
		if err != nil {
			log.Errorf("DEBUG: Failed to parse target %s: %v", targetName, err)
			allErrors = errors.Join(allErrors, err)
			continue
		}
		r.applyOptions(target.Options)

		data, err := r.toFormat(target.Format)
		if err != nil {
			log.Errorf("DEBUG: Failed to format target %s: %v", targetName, err)
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if !bytes.HasSuffix(data, []byte{'\n'}) {
			data = append(data, "\n"...)
		}

		if _, err := target.Write(data); err != nil {
			log.Errorf("DEBUG: Failed to write target %s: %v", targetName, err)
			allErrors = errors.Join(allErrors, err)
		} else {
			log.Debugf("DEBUG: Successfully wrote target: %s", targetName)
		}
	}
	return
}

// toFormat converts the report into the given format.
func (r *Report) toFormat(format string) (data []byte, err error) {
	log.Debugf("DEBUG: toFormat called with format: %s", format)
	switch format {
	case JSON:
		log.Debugf("DEBUG: Generating JSON format")
		data, err = json.Marshal(r)
	case YAML:
		log.Debugf("DEBUG: Generating YAML format")
		data, err = yaml.Marshal(r)
	case Text:
		log.Debugf("DEBUG: Generating Text format")
		data, err = generateTextReport(r)
	case AppStudio, HACBS:
		log.Debugf("DEBUG: Generating Appstudio format")
		data, err = json.Marshal(r.toAppstudioReport())
	case Summary:
		log.Debugf("DEBUG: Generating Summary format")
		data, err = json.Marshal(r.toSummary())
	case SummaryMarkdown:
		log.Debugf("DEBUG: Generating Markdown format")
		data, err = generateMarkdownSummary(r)
	case JUnit:
		log.Debugf("DEBUG: Generating XML format")
		data, err = xml.Marshal(r.toJUnit())
	case Attestation:
		log.Debugf("DEBUG: Generating Attestation format")
		data, err = r.renderAttestations()
	case PolicyInput:
		log.Debugf("DEBUG: Generating PolicyInput format")
		data = bytes.Join(r.PolicyInput, []byte("\n"))
	case VSA:
		log.Debugf("DEBUG: Generating VSA format")
		data, err = r.toVSA()
	default:
		log.Errorf("DEBUG: Unknown format: %s", format)
		return nil, fmt.Errorf("%q is not a valid report format", format)
	}
	return
}

func (r *Report) toVSA() ([]byte, error) {
	generator := NewSnapshotVSAGenerator(*r)
	predicate, err := generator.GeneratePredicate(context.Background())
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(predicate)
}

// toSummary returns a condensed version of the report.
func (r *Report) toSummary() summary {
	pr := summary{
		Snapshot: r.Snapshot,
	}
	for _, cmp := range r.Components {
		if !cmp.Success {
			pr.Success = false
		}
		c := componentSummary{
			TotalViolations: len(cmp.Violations),
			TotalWarnings:   len(cmp.Warnings),

			// Because cmp.Successes does not get populated unless the --show-successes
			// flag was set, cmp.SuccessCount is used here instead of len(cmp.Successes)
			TotalSuccesses: cmp.SuccessCount,

			Success:    cmp.Success,
			Name:       cmp.Name,
			Violations: condensedMsg(cmp.Violations),
			Warnings:   condensedMsg(cmp.Warnings),
			Successes:  condensedMsg(cmp.Successes),
		}
		pr.Components = append(pr.Components, c)
	}
	pr.Key = r.Key
	return pr
}

func (r *Report) applyOptions(opts format.Options) {
	r.ShowSuccesses = opts.ShowSuccesses
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

func generateMarkdownSummary(r *Report) ([]byte, error) {
	var markdownBuffer bytes.Buffer
	markdownBuffer.WriteString("| Field     | Value |Status|\n")
	markdownBuffer.WriteString("|-----------|-------|-------|\n")

	var totalViolations, totalWarnings, totalSuccesses int
	pr := r.toSummary()
	for _, component := range pr.Components {
		totalViolations += component.TotalViolations
		totalWarnings += component.TotalWarnings
		totalSuccesses += component.TotalSuccesses
	}

	writeIcon := func(condition bool) string {
		if condition {
			return ":white_check_mark:"
		}
		return ":x:"
	}

	writeMarkdownField(&markdownBuffer, "Time", r.created.UTC().Format("2006-01-02 15:04:05"), "")
	writeMarkdownField(&markdownBuffer, "Successes", totalSuccesses, writeIcon(totalSuccesses >= 1 && totalViolations == 0))
	writeMarkdownField(&markdownBuffer, "Failures", totalViolations, writeIcon(totalViolations == 0))
	writeMarkdownField(&markdownBuffer, "Warnings", totalWarnings, writeIcon(totalWarnings == 0))
	writeMarkdownField(&markdownBuffer, "Result", "", writeIcon(r.Success))
	return markdownBuffer.Bytes(), nil
}

//go:embed templates/*.tmpl
var efs embed.FS

func generateTextReport(r *Report) ([]byte, error) {
	// Prepare some template input
	input := struct {
		Report     *Report
		TestReport TestReport
	}{
		// This includes everything in the yaml/json output
		Report: r,
		// This has useful stuff we want to output, so let's reuse it
		// even though this is not what it was originally designed for
		TestReport: r.toAppstudioReport(),
	}

	return utils.RenderFromTemplatesWithMain(input, "text_report.tmpl", efs)
}

func writeMarkdownField(buffer *bytes.Buffer, name string, value any, icon string) {
	valueStr := fmt.Sprintf("%v", value)
	buffer.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, valueStr, icon))
}

// toAppstudioReport returns a version of the report that conforms to the
// TEST_OUTPUT format, usually written to the TEST_OUTPUT Tekton task result
func (r *Report) toAppstudioReport() TestReport {
	log.Debugf("DEBUG: Generating appstudio report for %d components", len(r.Components))
	result := TestReport{
		Timestamp: fmt.Sprint(r.created.UTC().Unix()),
		// EC generally runs with the AllNamespaces flag set to true
		// and policies from many namespaces. Rather than try to list
		// them all in this string field we just leave it blank.
		Namespace: "",
	}

	hasFailures := false
	for i, component := range r.toSummary().Components {
		log.Debugf("DEBUG: Processing component %d: %s (success: %t, violations: %d, warnings: %d, successes: %d)",
			i, component.Name, component.Success, component.TotalViolations, component.TotalWarnings, component.TotalSuccesses)
		result.Failures += component.TotalViolations
		result.Warnings += component.TotalWarnings
		result.Successes += component.TotalSuccesses

		if !component.Success {
			// It is possible, although quite unusual, that a component has no
			// listed violations but is still marked as not successful.
			hasFailures = true
			log.Debugf("DEBUG: Component %s marked as unsuccessful", component.Name)
		}
	}

	log.Debugf("DEBUG: Final appstudio report - successes: %d, failures: %d, warnings: %d, hasFailures: %t",
		result.Successes, result.Failures, result.Warnings, hasFailures)
	result.DeriveResult(hasFailures)
	log.Debugf("DEBUG: Appstudio report result: %s", result.Result)
	return result
}

func (r *TestReport) DeriveResult(hasFailures bool) {
	switch {
	case r.Failures > 0 || hasFailures:
		r.Result = "FAILURE"
	case r.Warnings > 0:
		r.Result = "WARNING"
	case r.Successes == 0:
		r.Result = "SKIPPED"
	default:
		r.Result = "SUCCESS"
	}
}

// It's redundant and perhaps not very useful, but let's produce some kind of
// a human readable note. We could perhaps make this more sophisticated in future,
// e.g. by including an abbreviated list of failure or warning messages.
func (r *TestReport) DeriveNote() {
	switch {
	case r.Result == "FAILURE":
		r.Note = "Failures detected"
	case r.Result == "WARNING":
		r.Note = "Warnings detected"
	case r.Result == "SKIPPED":
		r.Note = "All checks were skipped"
	case r.Result == "SUCCESS":
		r.Note = "All checks passed successfully"
	}
}

func OutputAppstudioReport(t TestReport) {
	out, err := json.Marshal(t)
	if err != nil {
		// Unlikely
		panic(err)
	}
	fmt.Printf("%s\n", out)
}

func AppstudioReportForError(prefix string, err error) TestReport {
	return TestReport{
		Timestamp: fmt.Sprint(time.Now().UTC().Unix()),
		Namespace: "",
		Successes: 0,
		Warnings:  0,
		Failures:  0,
		Result:    "ERROR",
		Note:      fmt.Sprintf("Error: %s: %s", prefix, err.Error()),
	}
}
