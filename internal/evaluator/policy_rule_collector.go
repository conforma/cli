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
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/opa"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// PolicyRuleCollector handles the collection and processing of policy rules
// from various policy sources, including both annotated and non-annotated rules.
type PolicyRuleCollector struct {
	fs afero.Fs
}

// NewPolicyRuleCollector creates a new PolicyRuleCollector instance.
func NewPolicyRuleCollector(fs afero.Fs) *PolicyRuleCollector {
	return &PolicyRuleCollector{
		fs: fs,
	}
}

// CollectRulesResult contains the collected rules and any errors encountered.
type CollectRulesResult struct {
	AnnotatedRules    policyRules
	NonAnnotatedRules nonAnnotatedRules
	AllRules          policyRules
	Error             error
}

// CollectRulesFromSources collects all rules from the given policy sources.
func (prc *PolicyRuleCollector) CollectRulesFromSources(
	ctx context.Context,
	policySources []source.PolicySource,
	workDir string,
) CollectRulesResult {
	rules := policyRules{}
	nonAnnotatedRules := nonAnnotatedRules{}

	// Download and process all policy sources
	for _, s := range policySources {
		dir, err := s.GetPolicy(ctx, workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			return CollectRulesResult{Error: err}
		}

		annotations, err := prc.processPolicySource(ctx, s, dir)
		if err != nil {
			return CollectRulesResult{Error: err}
		}

		// Process annotations to collect rules
		prc.processAnnotations(annotations, rules, nonAnnotatedRules)
	}

	// Combine all rules for filtering
	allRules := prc.combineRules(rules, nonAnnotatedRules)

	return CollectRulesResult{
		AnnotatedRules:    rules,
		NonAnnotatedRules: nonAnnotatedRules,
		AllRules:          allRules,
	}
}

// processPolicySource processes a single policy source and returns its annotations.
func (prc *PolicyRuleCollector) processPolicySource(
	ctx context.Context,
	s source.PolicySource,
	dir string,
) ([]*ast.AnnotationsRef, error) {
	fs := utils.FS(ctx)

	// Only process policy subdirectories, not config or data subdirs
	if s.Subdir() != "policy" {
		return []*ast.AnnotationsRef{}, nil
	}

	annotations, err := opa.InspectDir(fs, dir)
	if err != nil {
		return nil, prc.handleInspectError(err, s.PolicyUrl())
	}

	return annotations, nil
}

// handleInspectError provides enhanced error messages for common policy source issues.
func (prc *PolicyRuleCollector) handleInspectError(err error, policyURL string) error {
	if err.Error() != "no rego files found in policy subdirectory" {
		return err
	}

	// Provide more helpful error messages for common URL issues
	parsedURL, parseErr := url.Parse(policyURL)
	if parseErr != nil {
		return err
	}

	// Check if this might be a GitHub/GitLab URL with wrong scheme
	pos := strings.LastIndex(parsedURL.Path, ".")
	if pos == -1 {
		if (parsedURL.Host == "github.com" || parsedURL.Host == "gitlab.com") &&
			(parsedURL.Scheme == "https" || parsedURL.Scheme == "http") {
			log.Debug("GitHub or GitLab, http transport, and no file extension, this could be a problem.")
			return fmt.Errorf("%s.\nYou've specified a %s URL with an %s:// scheme.\nDid you mean: %s instead?",
				err, parsedURL.Hostname(), parsedURL.Scheme,
				fmt.Sprint(parsedURL.Host+parsedURL.RequestURI()))
		}
	}

	return err
}

// processAnnotations processes annotations to collect both annotated and non-annotated rules.
func (prc *PolicyRuleCollector) processAnnotations(
	annotations []*ast.AnnotationsRef,
	rules policyRules,
	nonAnnotatedRules nonAnnotatedRules,
) {
	for _, a := range annotations {
		if a.Annotations != nil {
			// Rules with annotations - collect full metadata
			if err := rules.collect(a); err != nil {
				log.Errorf("Error collecting annotated rule: %v", err)
			}
		} else {
			// Rules without annotations - track for filtering only
			prc.processNonAnnotatedRule(a, nonAnnotatedRules)
		}
	}
}

// processNonAnnotatedRule processes a single non-annotated rule.
func (prc *PolicyRuleCollector) processNonAnnotatedRule(
	a *ast.AnnotationsRef,
	nonAnnotatedRules nonAnnotatedRules,
) {
	ruleRef := a.GetRule()
	if ruleRef == nil {
		return
	}

	// Extract package name from the rule path
	packageName := prc.extractPackageName(a.Path)

	// Try to extract code from rule body first, fallback to rule name
	code := extractCodeFromRuleBody(ruleRef)
	if code == "" {
		shortName := ruleRef.Head.Name.String()
		code = fmt.Sprintf("%s.%s", packageName, shortName)
	}

	log.Debugf("Non-annotated rule: packageName=%s, code=%s", packageName, code)

	// Track for filtering but don't add to rules map for success computation
	nonAnnotatedRules[code] = true
}

// extractPackageName extracts the package name from an annotation path.
func (prc *PolicyRuleCollector) extractPackageName(path []*ast.Term) string {
	if len(path) > 1 && len(path) >= 2 {
		// Path format is typically ["data", "package", "rule"]
		// We want the package part (index 1)
		return strings.ReplaceAll(path[1].String(), `"`, "")
	}
	return ""
}

// combineRules combines annotated and non-annotated rules for filtering.
func (prc *PolicyRuleCollector) combineRules(
	rules policyRules,
	nonAnnotatedRules nonAnnotatedRules,
) policyRules {
	allRules := make(policyRules)

	// Add annotated rules
	for code, rule := range rules {
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
