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

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
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

// PrintConsole outputs the unified result as console text
func (r *VSAValidationResult) PrintConsole(out io.Writer) error {
	// Show VSA result first
	if r.VSAPhaseResult != nil {
		// Show predicate outcome FIRST for better flow understanding
		if r.VSAPhaseResult.PredicateOutcome != "" {
			fmt.Fprintf(out, "   Predicate Outcome: %s\n", r.VSAPhaseResult.PredicateOutcome)
		}

		if r.VSAPhaseResult.Passed {
			fmt.Fprintln(out, "✅ VSA validation passed")
			if r.VSAPhaseResult.Message != "" {
				fmt.Fprintf(out, "   %s\n", r.VSAPhaseResult.Message)
			}
		} else {
			fmt.Fprintln(out, "❌ VSA validation failed")
			if r.VSAPhaseResult.Message != "" {
				fmt.Fprintf(out, "   %s\n", r.VSAPhaseResult.Message)
			}
		}
	}

	// Show image validation result if used
	if r.UsedFallback && r.ImageValidationResult != nil {
		fmt.Fprintln(out, "🔄 Using image validation...")

		if r.ImageValidationResult.Passed {
			fmt.Fprintln(out, "✅ Image validation passed")
		} else {
			fmt.Fprintln(out, "❌ Image validation failed")
		}

		// Show violation/warning counts only (detailed info is in structured error section)
		if len(r.ImageValidationResult.Violations) > 0 {
			fmt.Fprintf(out, "   Violations: %d\n", len(r.ImageValidationResult.Violations))
		}

		if len(r.ImageValidationResult.Warnings) > 0 {
			fmt.Fprintf(out, "   Warnings: %d\n", len(r.ImageValidationResult.Warnings))
		}
	}

	// Show summary
	fmt.Fprintln(out, "\nSummary:")
	if r.VSAPhaseResult != nil {
		if r.VSAPhaseResult.Passed {
			fmt.Fprintln(out, "  VSA Status: Passed")
		} else {
			fmt.Fprintln(out, "  VSA Status: Failed")
		}
	}

	if r.UsedFallback && r.ImageValidationResult != nil {
		if r.ImageValidationResult.Passed {
			fmt.Fprintln(out, "  Image Validation Status: Passed")
		} else {
			fmt.Fprintln(out, "  Image Validation Status: Failed")
		}
	}

	// Show overall status
	if r.OverallSuccess {
		if r.UsedFallback {
			fmt.Fprintln(out, "  Overall Status: ✅ PASSED (used fallback)")
		} else {
			fmt.Fprintln(out, "  Overall Status: ✅ PASSED")
		}
	} else {
		if r.UsedFallback {
			fmt.Fprintln(out, "  Overall Status: ❌ FAILED (fallback also failed)")
		} else {
			fmt.Fprintln(out, "  Overall Status: ❌ FAILED")
		}
	}

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

// ToImageValidationResult converts an image validation Output to the unified ImageValidationResult format
func ToImageValidationResult(output *output.Output) *ImageValidationResult {
	if output == nil {
		return nil
	}

	// Extract violations, warnings, and successes from the output
	violations := output.Violations()
	warnings := output.Warnings()
	successes := output.Successes()

	// Determine if image validation passed (no violations)
	passed := len(violations) == 0

	// Create image validation summary
	summary := &ImageValidationSummary{
		TotalViolations: len(violations),
		TotalWarnings:   len(warnings),
		TotalSuccesses:  len(successes),
	}

	return &ImageValidationResult{
		Passed:     passed,
		Violations: violations,
		Warnings:   warnings,
		Successes:  successes,
		Summary:    summary,
	}
}

// BuildUnifiedValidationResult creates a unified VSAValidationResult from VSA and image validation results
func BuildUnifiedValidationResult(vsaResult *ValidationResult, fallbackOutput *output.Output, usedFallback bool, imageRef string) *VSAValidationResult {
	// Convert VSA result
	unifiedVSAResult := ToVSAPhaseResult(vsaResult)

	// Convert image validation result
	var unifiedImageResult *ImageValidationResult
	if usedFallback && fallbackOutput != nil {
		unifiedImageResult = ToImageValidationResult(fallbackOutput)
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
