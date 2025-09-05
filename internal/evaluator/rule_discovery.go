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
	"fmt"
	"net/url"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// RuleDiscoveryService provides functionality to discover and collect rules
// from policy sources. This service is separate from evaluation to maintain
// clear separation of concerns.
type RuleDiscoveryService interface {
	// DiscoverRules discovers and collects all available rules from the given
	// policy sources. Returns a map of rule codes to rule information.
	DiscoverRules(ctx context.Context, policySources []source.PolicySource) (PolicyRules, error)

	// DiscoverRulesWithNonAnnotated discovers all rules (both annotated and non-annotated)
	// from policy sources. Returns both the annotated rules and a set of non-annotated rule codes.
	// This is used by the evaluator for comprehensive filtering.
	DiscoverRulesWithNonAnnotated(ctx context.Context, policySources []source.PolicySource) (PolicyRules, map[string]bool, error)

	// DiscoverRulesWithWorkDir discovers rules using a specific work directory.
	// This is used by the evaluator to ensure policies are downloaded to the same location.
	DiscoverRulesWithWorkDir(ctx context.Context, policySources []source.PolicySource, workDir string) (PolicyRules, map[string]bool, error)

	// CombineRulesForFiltering combines annotated and non-annotated rules into a single
	// PolicyRules map suitable for filtering. This encapsulates the logic for creating
	// minimal rule.Info structures for non-annotated rules.
	CombineRulesForFiltering(annotatedRules PolicyRules, nonAnnotatedRules map[string]bool) PolicyRules
}

type ruleDiscoveryService struct{}

// NewRuleDiscoveryService creates a new rule discovery service.
func NewRuleDiscoveryService() RuleDiscoveryService {
	return &ruleDiscoveryService{}
}

// DiscoverRules implements the RuleDiscoveryService interface by collecting
// all rules from the provided policy sources.
func (r *ruleDiscoveryService) DiscoverRules(ctx context.Context, policySources []source.PolicySource) (PolicyRules, error) {
	rules, _, err := r.DiscoverRulesWithNonAnnotated(ctx, policySources)
	return rules, err
}

// DiscoverRulesWithNonAnnotated discovers all rules (both annotated and non-annotated)
// from policy sources. This method provides the complete rule discovery functionality
// that was previously embedded in the evaluator.
func (r *ruleDiscoveryService) DiscoverRulesWithNonAnnotated(ctx context.Context, policySources []source.PolicySource) (PolicyRules, map[string]bool, error) {
	// Create a temporary work directory for downloading policy sources
	fs := utils.FS(ctx)
	workDir, err := utils.CreateWorkDir(fs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	return r.DiscoverRulesWithWorkDir(ctx, policySources, workDir)
}

// DiscoverRulesWithWorkDir discovers all rules (both annotated and non-annotated)
// from policy sources using a specific work directory. This is used by the evaluator
// to ensure policies are downloaded to the same location.
func (r *ruleDiscoveryService) DiscoverRulesWithWorkDir(ctx context.Context, policySources []source.PolicySource, workDir string) (PolicyRules, map[string]bool, error) {
	rules := PolicyRules{}
	nonAnnotatedRules := make(map[string]bool)
	noRegoFilesError := false

	// Download and collect rules from all policy sources
	for _, s := range policySources {
		dir, err := s.GetPolicy(ctx, workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s: %v", s.PolicyUrl(), err)
			return nil, nil, fmt.Errorf("failed to download policy source %s: %w", s.PolicyUrl(), err)
		}

		annotations := []*ast.AnnotationsRef{}

		// We only want to inspect the directory of policy subdirs, not config or data subdirs
		if s.Subdir() == "policy" {
			fs := utils.FS(ctx)
			annotations, err = opa.InspectDir(fs, dir)
			if err != nil {
				// Handle the case where no Rego files are found gracefully
				if err.Error() == "no rego files found in policy subdirectory" {
					log.Debugf("No Rego files found in policy subdirectory for %s", s.PolicyUrl())
					noRegoFilesError = true
					continue // Skip this source and continue with others
				}

				errMsg := err
				// Let's try to give some more robust messaging to the user
				policyURL, err := url.Parse(s.PolicyUrl())
				if err != nil {
					return nil, nil, errMsg
				}
				// Do we have a prefix at the end of the URL path?
				// If not, this means we aren't trying to access a specific file
				pos := strings.LastIndex(policyURL.Path, ".")
				if pos == -1 {
					// Are we accessing a GitHub or GitLab URL? If so, are we beginning with 'https' or 'http'?
					if (policyURL.Host == "github.com" || policyURL.Host == "gitlab.com") && (policyURL.Scheme == "https" || policyURL.Scheme == "http") {
						log.Debug("Git Hub or GitLab, http transport, and no file extension, this could be a problem.")
						errMsg = fmt.Errorf("%s.\nYou've specified a %s URL with an %s:// scheme.\nDid you mean: %s instead?", errMsg, policyURL.Hostname(), policyURL.Scheme, fmt.Sprint(policyURL.Host+policyURL.RequestURI()))
					}
				}
				return nil, nil, errMsg
			}
		}

		// Collect ALL rules for filtering purposes - both with and without annotations
		// This ensures that rules without metadata (like fail_with_data.rego) are properly included
		for _, a := range annotations {
			if a.Annotations != nil {
				// Rules with annotations - collect full metadata
				if err := rules.collect(a); err != nil {
					return nil, nil, fmt.Errorf("failed to collect rule from %s: %w", s.PolicyUrl(), err)
				}
			} else {
				// Rules without annotations - track for filtering only, not for success computation
				ruleRef := a.GetRule()
				if ruleRef != nil {
					// Extract package name from the rule path
					packageName := ""
					if len(a.Path) > 1 {
						// Path format is typically ["data", "package", "rule"]
						// We want the package part (index 1)
						if len(a.Path) >= 2 {
							packageName = strings.ReplaceAll(a.Path[1].String(), `"`, "")
						}
					}

					// Try to extract code from rule body first, fallback to rule name
					code := extractCodeFromRuleBody(ruleRef)

					// If no code found in body, use rule name
					if code == "" {
						shortName := ruleRef.Head.Name.String()
						code = fmt.Sprintf("%s.%s", packageName, shortName)
					}

					// Debug: Print non-annotated rule processing
					log.Debugf("Non-annotated rule: packageName=%s, code=%s", packageName, code)

					// Track for filtering but don't add to rules map for success computation
					nonAnnotatedRules[code] = true
				}
			}
		}
	}

	log.Debugf("Discovered %d annotated rules and %d non-annotated rules from %d policy sources",
		len(rules), len(nonAnnotatedRules), len(policySources))

	// If no rego files were found in any policy source and no rules were discovered,
	// return the original error message for backward compatibility.
	// This maintains the expected behavior for the acceptance test scenario where
	// a policy repository is downloaded but contains no valid rego files.
	if noRegoFilesError && len(rules) == 0 && len(nonAnnotatedRules) == 0 {
		return nil, nil, fmt.Errorf("no rego files found in policy subdirectory")
	}

	return rules, nonAnnotatedRules, nil
}

// CombineRulesForFiltering combines annotated and non-annotated rules into a single
// PolicyRules map suitable for filtering. This method encapsulates the logic for
// creating minimal rule.Info structures for non-annotated rules.
func (r *ruleDiscoveryService) CombineRulesForFiltering(annotatedRules PolicyRules, nonAnnotatedRules map[string]bool) PolicyRules {
	// Start with all annotated rules
	allRules := make(PolicyRules)
	for code, rule := range annotatedRules {
		allRules[code] = rule
	}

	// Add non-annotated rules as minimal rule.Info for filtering
	for code := range nonAnnotatedRules {
		parts := strings.Split(code, ".")
		if len(parts) >= 2 {
			packageName := parts[len(parts)-2]
			shortName := parts[len(parts)-1]
			allRules[code] = rule.Info{
				Code:      code,
				Package:   packageName,
				ShortName: shortName,
			}
		}
	}

	return allRules
}
