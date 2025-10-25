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

package evaluator

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

// ResultProcessor handles the processing, filtering, and categorization of evaluation results.
type ResultProcessor struct {
	policyResolver PolicyResolver
}

// NewResultProcessor creates a new ResultProcessor instance.
func NewResultProcessor(policyResolver PolicyResolver) *ResultProcessor {
	return &ResultProcessor{
		policyResolver: policyResolver,
	}
}

// ProcessResult processes a single evaluation result, applying filtering and categorization.
func (rp *ResultProcessor) ProcessResult(
	ctx context.Context,
	result Outcome,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) (Outcome, map[string]bool, error) {
	// Create unified filter for consistent filtering logic
	unifiedFilter := NewUnifiedPostEvaluationFilter(rp.policyResolver)

	// Collect all results for processing
	allResults := rp.collectAllResults(result)

	// Add metadata to all results
	for j := range allResults {
		addRuleMetadata(ctx, &allResults[j], rules)
	}

	// Filter results using the unified filter
	filteredResults, updatedMissingIncludes := unifiedFilter.FilterResults(
		allResults, rules, target, missingIncludes, effectiveTime)

	// Categorize results using the unified filter
	warnings, failures, exceptions, skipped := unifiedFilter.CategorizeResults(
		filteredResults, result, effectiveTime)

	// Update the result with processed data
	result.Warnings = warnings
	result.Failures = failures
	result.Exceptions = exceptions
	result.Skipped = skipped

	// Compute successes
	result.Successes = rp.computeSuccesses(result, rules, target, updatedMissingIncludes, unifiedFilter)

	return result, updatedMissingIncludes, nil
}

// collectAllResults collects all result types into a single slice for processing.
func (rp *ResultProcessor) collectAllResults(result Outcome) []Result {
	allResults := make([]Result, 0, len(result.Warnings)+len(result.Failures)+len(result.Exceptions)+len(result.Skipped))
	allResults = append(allResults, result.Warnings...)
	allResults = append(allResults, result.Failures...)
	allResults = append(allResults, result.Exceptions...)
	allResults = append(allResults, result.Skipped...)
	return allResults
}

// computeSuccesses generates success results for rules that passed.
func (rp *ResultProcessor) computeSuccesses(
	result Outcome,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	unifiedFilter PostEvaluationFilter,
) []Result {
	// Track which rules we've seen in the results
	seenRules := rp.getSeenRules(result)

	var successes []Result
	if len(rules) > 0 {
		successes = make([]Result, 0, len(rules))
	}

	// Any rule left DID NOT get metadata added so it's a success
	for code, rule := range rules {
		if _, ok := seenRules[code]; ok {
			continue
		}

		// Ignore any successes that are not meant for the package this CheckResult represents
		if rule.Package != result.Namespace {
			continue
		}

		success := rp.createSuccessResult(code, rule)

		// Apply filtering to determine if this success should be included
		if !rp.shouldIncludeSuccess(success, rules, target, missingIncludes, unifiedFilter) {
			log.Debugf("Skipping result success: %#v", success)
			continue
		}

		successes = append(successes, success)
	}

	return successes
}

// getSeenRules returns a map of rule codes that have been seen in the results.
func (rp *ResultProcessor) getSeenRules(result Outcome) map[string]bool {
	seenRules := make(map[string]bool)
	for _, o := range [][]Result{result.Failures, result.Warnings, result.Skipped, result.Exceptions} {
		for _, r := range o {
			if code, ok := r.Metadata[metadataCode].(string); ok {
				seenRules[code] = true
			}
		}
	}
	return seenRules
}

// createSuccessResult creates a success result for a given rule.
func (rp *ResultProcessor) createSuccessResult(code string, rule rule.Info) Result {
	success := Result{
		Message: "Pass",
		Metadata: map[string]interface{}{
			metadataCode: code,
		},
	}

	if rule.Title != "" {
		success.Metadata[metadataTitle] = rule.Title
	}

	if rule.Description != "" {
		success.Metadata[metadataDescription] = rule.Description
	}

	if len(rule.Collections) > 0 {
		success.Metadata[metadataCollections] = rule.Collections
	}

	if len(rule.DependsOn) > 0 {
		success.Metadata[metadataDependsOn] = rule.DependsOn
	}

	if rule.EffectiveOn != "" {
		success.Metadata[metadataEffectiveOn] = rule.EffectiveOn
	}

	return success
}

// shouldIncludeSuccess determines if a success result should be included based on filtering rules.
func (rp *ResultProcessor) shouldIncludeSuccess(
	success Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	unifiedFilter PostEvaluationFilter,
) bool {
	if unifiedFilter != nil {
		// Use the unified filter to check if this success should be included
		filteredResults, _ := unifiedFilter.FilterResults(
			[]Result{success}, rules, target, missingIncludes, time.Now())

		return len(filteredResults) > 0
	}

	// Fallback to legacy filtering for backward compatibility
	// This would need to be implemented if legacy support is required
	return true
}
