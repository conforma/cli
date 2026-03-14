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
	"fmt"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// ValidationError represents a structured validation error with causes
type ValidationError struct {
	Message string  `json:"message"`
	Causes  []Cause `json:"causes"`
}

// Cause represents a specific cause of validation failure
type Cause struct {
	Type      string  `json:"type"` // "vsa", "fallback", "network", "policy", etc.
	Message   string  `json:"message"`
	Details   string  `json:"details,omitempty"`
	SubCauses []Cause `json:"sub_causes,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
	Severity  string  `json:"severity,omitempty"` // "error", "warning", "info"
}

// ErrorType constants
const (
	ErrorTypeVSA       = "vsa"
	ErrorTypeFallback  = "fallback"
	ErrorTypeNetwork   = "network"
	ErrorTypePolicy    = "policy"
	ErrorTypeSignature = "signature"
	ErrorTypeTimeout   = "timeout"
	ErrorTypeRetrieval = "retrieval"
)

// Severity constants
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// Error implements the error interface
func (ve *ValidationError) Error() string {
	if ve == nil {
		return ""
	}

	var parts []string
	parts = append(parts, ve.Message)

	for _, cause := range ve.Causes {
		parts = append(parts, fmt.Sprintf("- %s: %s", cause.Type, cause.Message))
		if cause.Details != "" {
			parts = append(parts, fmt.Sprintf("  Details: %s", cause.Details))
		}
	}

	return strings.Join(parts, "\n")
}

// HumanReadable returns a formatted human-readable version of the error
func (ve *ValidationError) HumanReadable() string {
	if ve == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("❌ %s\n", ve.Message))

	for _, cause := range ve.Causes {
		builder.WriteString(fmt.Sprintf("\n%s Failure\n", cases.Title(language.English).String(cause.Type)))
		builder.WriteString(fmt.Sprintf("  Message: %s\n", cause.Message))

		if cause.Details != "" {
			builder.WriteString(fmt.Sprintf("  Details: %s\n", cause.Details))
		}

		if cause.Timestamp != "" {
			builder.WriteString(fmt.Sprintf("  Time: %s\n", cause.Timestamp))
		}

		if len(cause.SubCauses) > 0 {
			// Determine label based on severity
			label := "Violations"
			if len(cause.SubCauses) > 0 && cause.SubCauses[0].Severity == SeverityWarning {
				label = "Warnings"
			}
			builder.WriteString(fmt.Sprintf("  %s:\n", label))
			for _, subCause := range cause.SubCauses {
				builder.WriteString(fmt.Sprintf("    - %s\n", subCause.Message))
			}
		}
	}

	return builder.String()
}

// BuildValidationError creates a structured error from VSA and fallback results
func BuildValidationError(vsaResult *ValidationResult, fallbackResult *ImageValidationResult, vsaErr, fallbackErr error) *ValidationError {
	var causes []Cause

	// Add VSA failure cause
	if vsaErr != nil || (vsaResult != nil && !vsaResult.Passed) {
		vsaCause := buildVSACause(vsaResult, vsaErr)
		causes = append(causes, vsaCause)
	}

	// Add fallback failure cause
	if fallbackErr != nil || (fallbackResult != nil && !fallbackResult.Passed) {
		fallbackCause := buildFallbackCause(fallbackResult, fallbackErr)
		causes = append(causes, fallbackCause)
	}

	if len(causes) == 0 {
		return nil
	}

	message := "Validation failed"
	if len(causes) > 1 {
		message = "Both VSA and fallback validation failed"
	} else if len(causes) == 1 {
		message = fmt.Sprintf("%s validation failed", cases.Title(language.English).String(causes[0].Type))
	}

	return &ValidationError{
		Message: message,
		Causes:  causes,
	}
}

// buildVSACause creates a cause for VSA validation failure
func buildVSACause(vsaResult *ValidationResult, vsaErr error) Cause {
	cause := Cause{
		Type:      ErrorTypeVSA,
		Message:   "VSA validation failed",
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  SeverityError,
	}

	if vsaErr != nil {
		populateVSAErrorCause(&cause, vsaErr)
	} else if vsaResult != nil {
		populateVSAResultCause(&cause, vsaResult)
	}

	return cause
}

// populateVSAErrorCause populates cause from an error
func populateVSAErrorCause(cause *Cause, vsaErr error) {
	cause.Details = vsaErr.Error()
	errMsg := vsaErr.Error()

	subCause := categorizeVSAError(errMsg)
	if subCause != nil {
		cause.SubCauses = append(cause.SubCauses, *subCause)
	}
}

// categorizeVSAError categorizes a VSA error into a specific type
func categorizeVSAError(errMsg string) *Cause {
	switch {
	case strings.Contains(errMsg, "signature"):
		return &Cause{
			Type:    ErrorTypeSignature,
			Message: "Signature verification failed",
			Details: errMsg,
		}
	case strings.Contains(errMsg, "timeout"):
		return &Cause{
			Type:    ErrorTypeTimeout,
			Message: "VSA retrieval timeout",
			Details: errMsg,
		}
	case strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection"):
		return &Cause{
			Type:    ErrorTypeNetwork,
			Message: "Network error during VSA retrieval",
			Details: errMsg,
		}
	default:
		return nil
	}
}

// populateVSAResultCause populates cause from a VSA result
func populateVSAResultCause(cause *Cause, vsaResult *ValidationResult) {
	cause.Details = vsaResult.Message
	if vsaResult.PredicateOutcome != "" && vsaResult.PredicateOutcome != predicateStatusPassed {
		cause.SubCauses = append(cause.SubCauses, Cause{
			Type:    ErrorTypePolicy,
			Message: fmt.Sprintf("Predicate status: %s", vsaResult.PredicateOutcome),
			Details: vsaResult.Message,
		})
	}
}

// buildFallbackCause creates a cause for fallback validation failure
func buildFallbackCause(fallbackResult *ImageValidationResult, fallbackErr error) Cause {
	cause := Cause{
		Type:      ErrorTypeFallback,
		Message:   "Fallback validation failed",
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  SeverityError,
	}

	if fallbackErr != nil {
		cause.Details = fallbackErr.Error()
	} else if fallbackResult != nil {
		// Extract details from violations
		if len(fallbackResult.Violations) > 0 {
			cause.Details = fmt.Sprintf("%d policy violations found", len(fallbackResult.Violations))

			// Add sub-causes for each violation
			for _, violation := range fallbackResult.Violations {
				subCause := Cause{
					Type:     ErrorTypePolicy,
					Message:  violation.Message,
					Details:  "Policy violation",
					Severity: SeverityError,
				}
				cause.SubCauses = append(cause.SubCauses, subCause)
			}
		}

		// Add warnings as sub-causes with lower severity
		for _, warning := range fallbackResult.Warnings {
			subCause := Cause{
				Type:     ErrorTypePolicy,
				Message:  warning.Message,
				Details:  "Policy warning",
				Severity: SeverityWarning,
			}
			cause.SubCauses = append(cause.SubCauses, subCause)
		}
	}

	return cause
}

// BuildNetworkError creates a structured error for network-related failures
func BuildNetworkError(operation string, err error) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf("Network operation failed: %s", operation),
		Causes: []Cause{
			{
				Type:      ErrorTypeNetwork,
				Message:   fmt.Sprintf("Failed to %s", operation),
				Details:   err.Error(),
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  SeverityError,
			},
		},
	}
}

// BuildTimeoutError creates a structured error for timeout failures
func BuildTimeoutError(operation string, timeout time.Duration) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf("Operation timed out: %s", operation),
		Causes: []Cause{
			{
				Type:      ErrorTypeTimeout,
				Message:   fmt.Sprintf("Timeout after %v", timeout),
				Details:   fmt.Sprintf("Operation '%s' exceeded timeout of %v", operation, timeout),
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  SeverityError,
			},
		},
	}
}
