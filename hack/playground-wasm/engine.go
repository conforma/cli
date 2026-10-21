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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"sigs.k8s.io/yaml"
)

type playgroundReport struct {
	Success    bool               `json:"success"`
	Engine     string             `json:"engine"`
	Package    string             `json:"package,omitempty"`
	Modules    []string           `json:"modules,omitempty"`
	Violations []playgroundResult `json:"violations,omitempty"`
	Warnings   []playgroundResult `json:"warnings,omitempty"`
	Errors     []playgroundError  `json:"errors,omitempty"`
}

type playgroundResult struct {
	Rule    string `json:"rule"`
	Message string `json:"msg"`
	Value   any    `json:"value,omitempty"`
}

type playgroundError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type playgroundModule struct {
	Filename string
	Source   string
	Package  string
}

func evaluatePlayground(ctx context.Context, policyText string, inputText string) playgroundReport {
	return evaluatePlaygroundWithData(ctx, policyText, inputText, "")
}

func evaluatePlaygroundWithData(ctx context.Context, policyText string, inputText string, dataText string) playgroundReport {
	report := playgroundReport{
		Engine: "opa",
	}

	input, err := parseDocument(inputText)
	if err != nil {
		report.Errors = append(report.Errors, playgroundError{Stage: "input", Message: err.Error()})
		return report
	}

	data, err := parseOptionalDocument(dataText)
	if err != nil {
		report.Errors = append(report.Errors, playgroundError{Stage: "data", Message: err.Error()})
		return report
	}

	modules, err := parsePolicyModules(policyText)
	if err != nil {
		report.Errors = append(report.Errors, playgroundError{Stage: "rego", Message: err.Error()})
		return report
	}

	pkg := modules[0].Package
	report.Package = pkg
	for _, module := range modules {
		report.Modules = append(report.Modules, module.Filename)
	}

	for _, rule := range []string{"deny", "violation"} {
		values, err := evalRule(ctx, modules, input, data, pkg, rule)
		if err != nil {
			report.Errors = append(report.Errors, playgroundError{Stage: rule, Message: err.Error()})
			continue
		}
		report.Violations = append(report.Violations, normalizeResults(rule, values)...)
	}

	values, err := evalRule(ctx, modules, input, data, pkg, "warn")
	if err != nil {
		report.Errors = append(report.Errors, playgroundError{Stage: "warn", Message: err.Error()})
	} else {
		report.Warnings = append(report.Warnings, normalizeResults("warn", values)...)
	}

	report.Success = len(report.Errors) == 0 && len(report.Violations) == 0
	return report
}

func parseDocument(inputText string) (any, error) {
	inputText = strings.TrimSpace(inputText)
	if inputText == "" {
		return map[string]any{}, nil
	}

	var input any
	if err := json.Unmarshal([]byte(inputText), &input); err == nil {
		return input, nil
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(inputText))
	if err != nil {
		return nil, fmt.Errorf("document is not valid JSON or YAML: %w", err)
	}
	if err := json.Unmarshal(jsonBytes, &input); err != nil {
		return nil, fmt.Errorf("document is not valid JSON or YAML: %w", err)
	}
	return input, nil
}

func parseOptionalDocument(dataText string) (map[string]any, error) {
	if strings.TrimSpace(dataText) == "" {
		return nil, nil
	}
	data, err := parseDocument(dataText)
	if err != nil {
		return nil, err
	}
	dataMap, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("data must be a JSON or YAML object")
	}
	return dataMap, nil
}

func parsePolicyModules(policyText string) ([]playgroundModule, error) {
	var modules []playgroundModule
	var current strings.Builder
	currentName := "playground.rego"

	flush := func() {
		source := strings.TrimSpace(current.String())
		if source == "" {
			return
		}
		modules = append(modules, playgroundModule{
			Filename: currentName,
			Source:   source,
		})
		current.Reset()
	}

	for _, line := range strings.Split(policyText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# file:") {
			flush()
			currentName = strings.TrimSpace(strings.TrimPrefix(trimmed, "# file:"))
			if currentName == "" {
				return nil, fmt.Errorf("empty module filename in # file marker")
			}
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	flush()

	if len(modules) == 0 {
		return nil, fmt.Errorf("no Rego modules provided")
	}

	for i := range modules {
		module, err := ast.ParseModule(modules[i].Filename, modules[i].Source)
		if err != nil {
			return nil, err
		}
		modules[i].Package = strings.TrimPrefix(module.Package.Path.String(), "data.")
	}

	return modules, nil
}

func evalRule(ctx context.Context, modules []playgroundModule, input any, data map[string]any, pkg string, rule string) ([]any, error) {
	query := fmt.Sprintf("data.%s.%s", pkg, rule)
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Input(input),
	}
	for _, module := range modules {
		opts = append(opts, rego.Module(module.Filename, module.Source))
	}
	if data != nil {
		opts = append(opts, rego.Store(inmem.NewFromObject(data)))
	}

	resultSet, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}

	values := make([]any, 0, len(resultSet))
	for _, result := range resultSet {
		for _, expr := range result.Expressions {
			values = append(values, expr.Value)
		}
	}
	return values, nil
}

func normalizeResults(rule string, values []any) []playgroundResult {
	var results []playgroundResult
	for _, value := range values {
		results = appendValue(results, rule, value)
	}
	return results
}

func appendValue(results []playgroundResult, rule string, value any) []playgroundResult {
	switch v := value.(type) {
	case nil:
		return results
	case string:
		return append(results, playgroundResult{Rule: rule, Message: v})
	case bool:
		if v {
			return append(results, playgroundResult{Rule: rule, Message: fmt.Sprintf("%s matched", rule)})
		}
	case []any:
		for _, item := range v {
			results = appendValue(results, rule, item)
		}
	case map[string]any:
		results = appendMapValues(results, rule, v)
	default:
		return append(results, playgroundResult{Rule: rule, Message: fmt.Sprint(v), Value: value})
	}
	return results
}

func appendMapValues(results []playgroundResult, rule string, values map[string]any) []playgroundResult {
	if msg, ok := values["msg"].(string); ok {
		return append(results, playgroundResult{Rule: rule, Message: msg, Value: values})
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := values[key]
		if matched, ok := value.(bool); ok && matched {
			results = append(results, playgroundResult{Rule: rule, Message: key})
			continue
		}
		results = append(results, playgroundResult{
			Rule:    rule,
			Message: fmt.Sprintf("%s: %v", key, value),
			Value:   map[string]any{key: value},
		})
	}
	return results
}

func marshalReport(report playgroundReport) string {
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fallback, _ := json.Marshal(playgroundReport{
			Engine: "opa",
			Errors: []playgroundError{{
				Stage:   "marshal",
				Message: err.Error(),
			}},
		})
		return string(fallback)
	}
	return string(out)
}
