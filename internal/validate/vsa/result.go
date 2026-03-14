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

package vsa

import (
	"encoding/json"
	"fmt"
	"io"

	app "github.com/konflux-ci/application-api/api/v1alpha1"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	validate_utils "github.com/conforma/cli/internal/validate"
)

// VSAValidationResult represents the unified result structure for VSA validation with optional fallback
type VSAValidationResult struct {
	// VSA-specific results
	VSAPhaseResult *VSAPhaseResult `json:"vsa_phase_result,omitempty"`

	// Image validation results
	ImageValidationResult *ImageValidationResult `json:"image_validation_result,omitempty"`

	// Overall status
	OverallSuccess bool   `json:"overall_success"`
	UsedFallback   bool   `json:"used_fallback"`
	ImageRef       string `json:"image_ref"`

	// Summary
	Summary *ResultSummary `json:"summary,omitempty"`

	// Structured error information
	Error *ValidationError `json:"error,omitempty"`
}

// VSAPhaseResult represents the result of the VSA validation phase
type VSAPhaseResult struct {
	Passed           bool   `json:"passed"`
	Message          string `json:"message,omitempty"`
	Failed           string `json:"failed,omitempty"`
	Reason           string `json:"reason,omitempty"`            // Human-readable reason
	PredicateOutcome string `json:"predicate_outcome,omitempty"` // Outcome from VSA predicate
}

// ImageValidationResult represents the result of image validation
type ImageValidationResult struct {
	Passed     bool                    `json:"passed"`
	Violations []evaluator.Result      `json:"violations,omitempty"`
	Warnings   []evaluator.Result      `json:"warnings,omitempty"`
	Successes  []evaluator.Result      `json:"successes,omitempty"`
	Summary    *ImageValidationSummary `json:"summary,omitempty"`
}

// ImageValidationSummary represents the summary of image validation results
type ImageValidationSummary struct {
	TotalViolations int `json:"total_violations"`
	TotalWarnings   int `json:"total_warnings"`
	TotalSuccesses  int `json:"total_successes"`
}

// ResultSummary represents the overall summary of validation results
type ResultSummary struct {
	TotalViolations int `json:"total_violations"`
	TotalWarnings   int `json:"total_warnings"`
	TotalSuccesses  int `json:"total_successes"`
}

// PrintJSON outputs the unified result as JSON
func (r *VSAValidationResult) PrintJSON(out io.Writer) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// printVSAPhaseResult outputs the VSA phase result
func (r *VSAValidationResult) printVSAPhaseResult(out io.Writer) {
	if r.VSAPhaseResult == nil {
		return
	}

	if r.VSAPhaseResult.PredicateOutcome != "" {
		fmt.Fprintf(out, "   Predicate Outcome: %s\n", r.VSAPhaseResult.PredicateOutcome)
	}

	status := "✅ VSA validation passed"
	if !r.VSAPhaseResult.Passed {
		status = "❌ VSA validation failed"
	}
	fmt.Fprintln(out, status)

	if r.VSAPhaseResult.Message != "" {
		fmt.Fprintf(out, "   %s\n", r.VSAPhaseResult.Message)
	}
}

// printImageValidationResult outputs the image validation result
func (r *VSAValidationResult) printImageValidationResult(out io.Writer) {
	if !r.UsedFallback || r.ImageValidationResult == nil {
		return
	}

	fmt.Fprintln(out, "🔄 Using image validation...")

	status := "✅ Image validation passed"
	if !r.ImageValidationResult.Passed {
		status = "❌ Image validation failed"
	}
	fmt.Fprintln(out, status)

	if len(r.ImageValidationResult.Violations) > 0 {
		fmt.Fprintf(out, "   Violations: %d\n", len(r.ImageValidationResult.Violations))
	}
	if len(r.ImageValidationResult.Warnings) > 0 {
		fmt.Fprintf(out, "   Warnings: %d\n", len(r.ImageValidationResult.Warnings))
	}
}

// printSummary outputs the summary section
func (r *VSAValidationResult) printSummary(out io.Writer) {
	fmt.Fprintln(out, "\nSummary:")

	if r.VSAPhaseResult != nil {
		status := "Passed"
		if !r.VSAPhaseResult.Passed {
			status = "Failed"
		}
		fmt.Fprintf(out, "  VSA Status: %s\n", status)
	}

	if r.UsedFallback && r.ImageValidationResult != nil {
		status := "Passed"
		if !r.ImageValidationResult.Passed {
			status = "Failed"
		}
		fmt.Fprintf(out, "  Image Validation Status: %s\n", status)
	}

	r.printOverallStatus(out)
}

// printOverallStatus outputs the overall status line
func (r *VSAValidationResult) printOverallStatus(out io.Writer) {
	var status string
	switch {
	case r.OverallSuccess && r.UsedFallback:
		status = "  Overall Status: ✅ PASSED (used fallback)"
	case r.OverallSuccess:
		status = "  Overall Status: ✅ PASSED"
	case r.UsedFallback:
		status = "  Overall Status: ❌ FAILED (fallback also failed)"
	default:
		status = "  Overall Status: ❌ FAILED"
	}
	fmt.Fprintln(out, status)
}

// PrintConsole outputs the unified result as console text
func (r *VSAValidationResult) PrintConsole(out io.Writer) error {
	r.printVSAPhaseResult(out)
	r.printImageValidationResult(out)
	r.printSummary(out)

	// Show structured error information if available
	if r.Error != nil {
		fmt.Fprintln(out, "\nDetailed Error Information:")
		fmt.Fprint(out, r.Error.HumanReadable())
	}

	return nil
}

// ToVSAPhaseResult converts a VSA ValidationResult to the unified VSAPhaseResult format
func ToVSAPhaseResult(result *ValidationResult) *VSAPhaseResult {
	if result == nil {
		return nil
	}

	vsaResult := &VSAPhaseResult{
		Passed:           result.Passed,
		Message:          result.Message,
		PredicateOutcome: result.PredicateOutcome,
	}

	// Set Failed and Reason fields based on the result
	if !result.Passed {
		vsaResult.Failed = result.Message          // Specific error message (can be empty)
		vsaResult.Reason = "VSA validation failed" // Always the same generic reason
	}

	return vsaResult
}

// ToImageValidationResult converts an image validation Output to the unified ImageValidationResult format.
// It uses the same processing pipeline as the validate image command to ensure consistency.
// showSuccesses and outputFormats are optional - if not provided, defaults are used.
func ToImageValidationResult(
	output *output.Output,
	err error,
	comp app.SnapshotComponent,
	showSuccesses bool,
	outputFormats []string,
) *ImageValidationResult {
	if output == nil {
		return nil
	}

	// Use the shared processing pipeline from validate image command
	// This ensures both commands produce identical results
	component := validate_utils.ProcessOutputForImageValidation(
		output,
		err,
		comp,
		showSuccesses,
		outputFormats,
	)

	// Determine if image validation passed (same logic as Component.Success)
	passed := component.Success

	// Create image validation summary
	summary := &ImageValidationSummary{
		TotalViolations: len(component.Violations),
		TotalWarnings:   len(component.Warnings),
		TotalSuccesses:  len(component.Successes),
	}

	return &ImageValidationResult{
		Passed:     passed,
		Violations: component.Violations,
		Warnings:   component.Warnings,
		Successes:  component.Successes,
		Summary:    summary,
	}

}

// BuildUnifiedValidationResult creates a unified VSAValidationResult from VSA and image validation results
func BuildUnifiedValidationResult(
	vsaResult *ValidationResult,
	fallbackOutput *output.Output,
	fallbackErr error,
	comp app.SnapshotComponent,
	usedFallback bool,
	imageRef string,
	showSuccesses bool,
	outputFormats []string,
) *VSAValidationResult {
	// Convert VSA result
	unifiedVSAResult := ToVSAPhaseResult(vsaResult)

	// Convert image validation result using the shared processing pipeline
	var unifiedImageResult *ImageValidationResult
	if usedFallback && fallbackOutput != nil {
		unifiedImageResult = ToImageValidationResult(fallbackOutput, fallbackErr, comp, showSuccesses, outputFormats)
	}

	// Determine overall success
	overallSuccess := false
	if usedFallback && unifiedImageResult != nil {
		// If image validation was used, success depends on image validation result
		overallSuccess = unifiedImageResult.Passed
	} else if unifiedVSAResult != nil {
		// If no image validation, success depends on VSA result
		overallSuccess = unifiedVSAResult.Passed
	}

	// Create overall summary
	var summary *ResultSummary
	if unifiedImageResult != nil && unifiedImageResult.Summary != nil {
		summary = &ResultSummary{
			TotalViolations: unifiedImageResult.Summary.TotalViolations,
			TotalWarnings:   unifiedImageResult.Summary.TotalWarnings,
			TotalSuccesses:  unifiedImageResult.Summary.TotalSuccesses,
		}
	}

	// Build structured error if validation failed
	var validationError *ValidationError
	if !overallSuccess {
		validationError = BuildValidationError(vsaResult, unifiedImageResult, nil, nil)
	}

	return &VSAValidationResult{
		VSAPhaseResult:        unifiedVSAResult,
		ImageValidationResult: unifiedImageResult,
		OverallSuccess:        overallSuccess,
		UsedFallback:          usedFallback,
		ImageRef:              imageRef,
		Summary:               summary,
		Error:                 validationError,
	}
}
