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
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

// UnifiedFilterFactory creates filters that use the RuleSelector
type UnifiedFilterFactory struct {
	selector RuleSelector
}

// NewUnifiedFilterFactory creates a new unified filter factory
func NewUnifiedFilterFactory(selector RuleSelector) FilterFactory {
	return &UnifiedFilterFactory{
		selector: selector,
	}
}

// CreateFilters creates a single filter that uses the unified selector
func (f *UnifiedFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	return []RuleFilter{NewUnifiedRuleFilter(f.selector)}
}

// UnifiedRuleFilter implements RuleFilter using the unified selector
type UnifiedRuleFilter struct {
	selector RuleSelector
}

// NewUnifiedRuleFilter creates a new unified rule filter
func NewUnifiedRuleFilter(selector RuleSelector) RuleFilter {
	return &UnifiedRuleFilter{
		selector: selector,
	}
}

// Include determines if a package should be included based on the unified selector
func (f *UnifiedRuleFilter) Include(pkg string, rules []rule.Info) bool {
	// Convert rules to the format expected by the selector
	allRules := make(map[string]rule.Info)
	for _, rule := range rules {
		allRules[rule.Code] = rule
	}

	// Use the selector to determine if package should be included
	includedPackages := f.selector.PackagesToEvaluate(allRules)
	for _, includedPkg := range includedPackages {
		if includedPkg == pkg {
			log.Debugf("UnifiedRuleFilter: Package %s included", pkg)
			return true
		}
	}

	log.Debugf("UnifiedRuleFilter: Package %s excluded", pkg)
	return false
}
