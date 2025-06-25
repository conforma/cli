// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX‑License‑Identifier: Apache‑2.0

package evaluator

import (
	"encoding/json"
	"strings"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

//////////////////////////////////////////////////////////////////////////////
// Interfaces
//////////////////////////////////////////////////////////////////////////////

//  RuleFilter decides whether an entire package (namespace) should be
//  included in the evaluation set.
type RuleFilter interface {
	Include(pkg string, rules []rule.Info) bool
}

//  FilterFactory builds a slice of filters for a given `ecc.Source`.
type FilterFactory interface {
	CreateFilters(source ecc.Source) []RuleFilter
}

//////////////////////////////////////////////////////////////////////////////
// DefaultFilterFactory
//////////////////////////////////////////////////////////////////////////////

type DefaultFilterFactory struct{}

func NewDefaultFilterFactory() FilterFactory { return &DefaultFilterFactory{} }

func (f *DefaultFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	var filters []RuleFilter

	// ── 1. Pipeline‑intention ───────────────────────────────────────────────
	intentions := extractStringArrayFromRuleData(source, "pipeline_intention")
	if len(intentions) > 0 {
		filters = append(filters, NewPipelineIntentionFilter(intentions))
	}

	// ── 2. Include list (handles @collection / pkg / pkg.rule) ─────────────
	if source.Config != nil && len(source.Config.Include) > 0 {
		filters = append(filters, NewIncludeListFilter(source.Config.Include))
	}

	return filters
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter
//////////////////////////////////////////////////////////////////////////////

//  If `targetIntentions` is empty, the filter is a NO‑OP (includes everything).
type PipelineIntentionFilter struct{ targetIntentions []string }

func NewPipelineIntentionFilter(target []string) RuleFilter {
	return &PipelineIntentionFilter{targetIntentions: target}
}

func (f *PipelineIntentionFilter) Include(_ string, rules []rule.Info) bool {
	if len(f.targetIntentions) == 0 {
		return true // no filtering requested
	}
	for _, r := range rules {
		for _, pi := range r.PipelineIntention {
			for _, want := range f.targetIntentions {
				if pi == want {
					return true
				}
			}
		}
	}
	return false
}

//////////////////////////////////////////////////////////////////////////////
// IncludeListFilter
//////////////////////////////////////////////////////////////////////////////

//  Entries may be:
//   • "@collection"         – any rule whose metadata lists that collection
//   • "package"             – whole package
//   • "package.rule"        – rule‑scoped, still selects the whole package
type IncludeListFilter struct{ entries []string }

func NewIncludeListFilter(entries []string) RuleFilter {
	return &IncludeListFilter{entries: entries}
}

func (f *IncludeListFilter) Include(pkg string, rules []rule.Info) bool {
	for _, entry := range f.entries {
		switch {
		case entry == pkg:
			return true
		case strings.HasPrefix(entry, "@"):
			want := strings.TrimPrefix(entry, "@")
			for _, r := range rules {
				for _, c := range r.Collections {
					if c == want {
						return true
					}
				}
			}
		case strings.Contains(entry, "."):
			parts := strings.SplitN(entry, ".", 2)
			if len(parts) == 2 && parts[0] == pkg {
				return true
			}
		}
	}
	return false
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter – applies all filters (logical AND)
//////////////////////////////////////////////////////////////////////////////

type NamespaceFilter struct{ filters []RuleFilter }

func NewNamespaceFilter(filters ...RuleFilter) *NamespaceFilter {
	return &NamespaceFilter{filters: filters}
}

func (nf *NamespaceFilter) Filter(rules policyRules) []string {
	// group rules by package
	grouped := make(map[string][]rule.Info)
	for fqName, r := range rules {
		pkg := strings.SplitN(fqName, ".", 2)[0]
		if pkg == "" {
			pkg = fqName // fallback
		}
		grouped[pkg] = append(grouped[pkg], r)
	}

	var out []string
	for pkg, pkgRules := range grouped {
		include := true
		for _, flt := range nf.filters {
			ok := flt.Include(pkg, pkgRules)

			if !ok {
				include = false
				break
			}
		}

		if include {
			out = append(out, pkg)
		}
	}
	return out
}

//////////////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////////////

func filterNamespaces(r policyRules, filters ...RuleFilter) []string {
	return NewNamespaceFilter(filters...).Filter(r)
}

//  extractStringArrayFromRuleData returns a string slice for `key`.
func extractStringArrayFromRuleData(src ecc.Source, key string) []string {
	if src.RuleData == nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(src.RuleData.Raw, &m); err != nil {
		log.Debugf("ruleData parse error: %v", err)
		return nil
	}
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, i := range v {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
