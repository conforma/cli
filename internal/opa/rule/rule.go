// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/ast"
)

func title(a *ast.AnnotationsRef) string {
	if a == nil || a.Annotations == nil {
		return ""
	}

	return a.Annotations.Title
}

// xrefRegExp is used to detect asciidoc links in a string.
var xrefRegExp = regexp.MustCompile(`xref:(?:([^:]+):ROOT:(.+?)\.adoc#([^[]+)|[\w\.\$\#]+)\[([\w\s/\.]+)\]`)

func description(a *ast.AnnotationsRef) string {
	if a == nil || a.Annotations == nil {
		return ""
	}

	// Unlink asciidoc text to avoid unexpected output
	return xrefRegExp.ReplaceAllString(a.Annotations.Description, "$4")
}

func customAnnotationString(a *ast.AnnotationsRef, fieldName string) string {
	if a == nil || a.Annotations == nil || a.Annotations.Custom == nil {
		return ""
	}

	if value, ok := a.Annotations.Custom[fieldName]; ok {
		switch value := value.(type) {
		case string:
			return replaceXrefReferencesWithURL(value)
		case time.Time:
			return value.Format(time.RFC3339)
		}
	}

	return ""
}

// replace all ascii doc
func replaceXrefReferencesWithURL(input string) string {
	return xrefRegExp.ReplaceAllStringFunc(input, func(match string) string {
		matches := xrefRegExp.FindStringSubmatch(match)
		// Expected capture groups:
		// matches[0]: full match
		// matches[1]: group (only in full variant)
		// matches[2]: filename (only in full variant)
		// matches[3]: anchor (only in full variant)
		// matches[4]: label (always captured)
		if len(matches) < 5 {
			return match
		}
		// Only perform URL replacement if all full-variant groups are present.
		if matches[1] == "" || matches[2] == "" || matches[3] == "" {
			return match
		}
		group := matches[1]
		filename := matches[2]
		anchor := matches[3]
		return "https://conforma.dev/docs/" + group + "/" + filename + ".html#" + anchor
	})
}

func effectiveOn(a *ast.AnnotationsRef) string {
	return customAnnotationString(a, "effective_on")
}

func solution(a *ast.AnnotationsRef) string {
	return xrefRegExp.ReplaceAllString(customAnnotationString(a, "solution"), "$4")
}

func lastTerm(a *ast.AnnotationsRef) string {
	if a == nil || len(a.Path) == 0 {
		return ""
	}

	lastTerm := a.Path[len(a.Path)-1]

	return strings.Trim(lastTerm.String(), `"`)
}

func kind(a *ast.AnnotationsRef) RuleKind {
	switch lastTerm(a) {
	case "deny":
		return Deny
	case "warn":
		return Warn
	default:
		return Other
	}
}

func shortName(a *ast.AnnotationsRef) string {
	if a == nil || a.Annotations == nil || a.Annotations.Custom == nil {
		return ""
	}

	shortName, ok := a.Annotations.Custom["short_name"]

	if !ok {
		return ""
	}

	return fmt.Sprint(shortName)
}

func collections(a *ast.AnnotationsRef) []string {
	collections := make([]string, 0, 3)
	if a == nil || a.Annotations == nil || a.Annotations.Custom == nil {
		return collections
	}

	if values, ok := a.Annotations.Custom["collections"].([]any); ok {
		for _, value := range values {
			if collection, ok := value.(string); ok {
				collections = append(collections, collection)
			}
		}
	}

	return collections
}

func pipelineIntention(a *ast.AnnotationsRef) []string {
	pipelineIntentions := make([]string, 0, 3)
	if a == nil || a.Annotations == nil || a.Annotations.Custom == nil {
		return pipelineIntentions
	}

	if values, ok := a.Annotations.Custom["pipeline_intention"].([]any); ok {
		for _, value := range values {
			if intention, ok := value.(string); ok {
				pipelineIntentions = append(pipelineIntentions, intention)
			}
		}
	}

	return pipelineIntentions
}

func packages(a *ast.AnnotationsRef) []string {
	packages := []string{}
	if a == nil {
		return packages
	}

	pkg := a.GetPackage()
	var path ast.Ref
	if pkg == nil {
		// odd, let's try Paths instead
		l := len(a.Path)
		if a.Path == nil || l == 0 {
			return packages
		}

		// we're dealing with rule's path so drop the last term which contains
		// the rule itself
		path = a.Path[0 : l-1]
	} else {
		path = pkg.Path
	}

	l := len(path)
	if l == 0 {
		return packages
	}

	packages = make([]string, 0, l)

	for _, p := range path {
		packages = append(packages, strings.Trim(p.Value.String(), `"`))
	}

	if len(packages) > 0 && packages[0] == "data" {
		packages = packages[1:]
	}

	return packages
}

func packageName(a *ast.AnnotationsRef) string {
	return strings.Join(packages(a), ".")
}

func code(a *ast.AnnotationsRef) string {
	if a == nil {
		return ""
	}

	return fmt.Sprintf("%s.%s", packageName(a), shortName(a))
}

func documentationUrl(a *ast.AnnotationsRef) string {
	if a == nil {
		return ""
	}

	// This makes assumptions about the way we publish policy docs for
	// policies defined in https://github.com/conforma/policy/
	// to https://conforma.dev/docs/policy/index.html . We should figure
	// out a way for the documentationUrl to be configurable, perhaps by using
	// some additional package annotations. To make matters even worse, we're now
	// hard coding "release_policy" in the URL, which is guaranteed wrong for
	// policies that are not defined under
	// https://github.com/conforma/policy/tree/main/policy/release
	// Given all this, the documentationUrl is not really reliable. We could remove it
	// entirely, but since it's used only the `ec inspect policy` output, let's live
	// with its flaws for now and fix it later.
	ruleDocUrlFormat := "https://conforma.dev/docs/policy/release_policy.html#%s__%s"

	// a.Path might be something like this: "data.foo.deny" or
	// "data.some.path.foo.warn". We want to pick out just "foo".
	pathStrings := strings.Split(a.Path.String(), ".")
	lenPathStrings := len(pathStrings)

	shortName := shortName(a)

	if lenPathStrings > 2 && pathStrings[lenPathStrings-2] != "" && shortName != "" {
		return fmt.Sprintf(ruleDocUrlFormat, pathStrings[lenPathStrings-2], shortName)
	}

	return ""
}

func dependsOn(a *ast.AnnotationsRef) []string {
	if a == nil {
		return []string{}
	}

	dependsOn, ok := a.Annotations.Custom["depends_on"]

	if !ok {
		return []string{}
	}

	switch d := dependsOn.(type) {
	case []any:
		ret := make([]string, 0, len(d))
		for _, v := range d {
			ret = append(ret, fmt.Sprint(v))
		}
		return ret
	default:
		return []string{fmt.Sprint(d)}
	}
}

type RuleKind string

const (
	Deny  RuleKind = "deny"
	Warn  RuleKind = "warn"
	Other RuleKind = "other"
)

type Info struct {
	Code              string
	Collections       []string
	DependsOn         []string
	Description       string
	DocumentationUrl  string
	Severity          string
	EffectiveOn       string
	Kind              RuleKind
	Package           string
	PipelineIntention []string
	ShortName         string
	Solution          string
	Title             string
}

func RuleInfo(a *ast.AnnotationsRef) Info {
	return Info{
		Code:              code(a),
		Collections:       collections(a),
		Description:       description(a),
		DependsOn:         dependsOn(a),
		DocumentationUrl:  documentationUrl(a),
		EffectiveOn:       effectiveOn(a),
		Solution:          solution(a),
		Kind:              kind(a),
		Package:           packageName(a),
		PipelineIntention: pipelineIntention(a),
		ShortName:         shortName(a),
		Title:             title(a),
	}
}
