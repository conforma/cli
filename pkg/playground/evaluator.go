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

// Package playground provides a small browser-safe evaluator for Conforma policy
// authoring playgrounds.
package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/opa/rule"
)

const (
	metadataCode        = "code"
	metadataCollections = "collections"
	metadataDependsOn   = "depends_on"
	metadataDescription = "description"
	metadataEffectiveOn = "effective_on"
	metadataSeverity    = "severity"
	metadataSolution    = "solution"
	metadataTitle       = "title"
	defaultPolicyFile   = "playground.rego"
)

var (
	failureRulePattern = regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
	warningRulePattern = regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
)

var disallowedBuiltins = map[string]bool{
	"opa.runtime":        true,
	"http.send":          true,
	"net.lookup_ip_addr": true,
}

// Request contains inline policy playground inputs.
type Request struct {
	Policy  string
	Input   string
	Data    string
	Package string
}

// Response is intentionally close to the validate input report shape, but only
// includes fields needed by an in-browser policy authoring loop.
type Response struct {
	Success      bool     `json:"success"`
	SuccessCount int      `json:"success-count"`
	Package      string   `json:"package,omitempty"`
	Modules      []string `json:"modules,omitempty"`
	Violations   []Result `json:"violations,omitempty"`
	Warnings     []Result `json:"warnings,omitempty"`
	Successes    []Result `json:"successes,omitempty"`
}

// Result mirrors Conforma result JSON: policy messages live in msg, and
// Conforma/OPA rule annotations live under metadata.
type Result struct {
	Message  string         `json:"msg"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Outputs  []string       `json:"outputs,omitempty"`

	ruleName string
}

type module struct {
	Filename string
	Source   string
	Package  string
	AST      *ast.Module
}

type ruleMetadata struct {
	RuleName string
	Kind     ruleKind
	Info     rule.Info
}

type ruleKind string

const (
	failure ruleKind = "failure"
	warning ruleKind = "warning"
)

// Evaluate runs inline Rego over inline JSON/YAML input and optional inline
// JSON/YAML data. It does not resolve remote policy sources or validate images.
func Evaluate(ctx context.Context, request Request) (Response, error) {
	input, err := parseDocument(request.Input)
	if err != nil {
		return Response{}, fmt.Errorf("parse input: %w", err)
	}

	data, err := parseData(request.Data)
	if err != nil {
		return Response{}, fmt.Errorf("parse data: %w", err)
	}

	modules, err := parseModules(request.Policy)
	if err != nil {
		return Response{}, fmt.Errorf("parse policy: %w", err)
	}

	pkg := request.Package
	if pkg == "" {
		pkg = modules[0].Package
	}

	compiler, err := compileModules(modules)
	if err != nil {
		return Response{}, fmt.Errorf("compile policy: %w", err)
	}

	rules, err := collectRuleMetadata(modules, pkg)
	if err != nil {
		return Response{}, fmt.Errorf("collect metadata: %w", err)
	}

	response := Response{
		Package: pkg,
	}
	for _, module := range modules {
		response.Modules = append(response.Modules, module.Filename)
	}

	for _, ruleName := range uniqueRuleNames(rules) {
		results, err := evalRule(ctx, compiler, data, input, pkg, ruleName)
		if err != nil {
			return Response{}, fmt.Errorf("evaluate %s.%s: %w", pkg, ruleName, err)
		}
		for _, result := range results {
			result.ruleName = ruleName
			metadata := metadataForResult(result, rules, ruleName)
			addRuleMetadata(&result, metadata.Info)
			switch metadata.Kind {
			case failure:
				response.Violations = append(response.Violations, result)
			case warning:
				response.Warnings = append(response.Warnings, result)
			}
		}
	}

	response.Successes = successes(rules, response.Violations, response.Warnings)
	response.SuccessCount = len(response.Successes)
	response.Success = len(response.Violations) == 0
	return response, nil
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

func parseData(dataText string) (map[string]any, error) {
	if strings.TrimSpace(dataText) == "" {
		return map[string]any{}, nil
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

func parseModules(policyText string) ([]module, error) {
	var modules []module
	var current strings.Builder
	currentName := defaultPolicyFile

	flush := func() {
		source := strings.TrimSpace(current.String())
		if source == "" {
			return
		}
		modules = append(modules, module{
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
		parsed, err := ast.ParseModuleWithOpts(modules[i].Filename, modules[i].Source, ast.ParserOptions{
			Capabilities:      playgroundCapabilities(),
			ProcessAnnotation: true,
		})
		if err != nil {
			return nil, err
		}
		modules[i].Package = strings.TrimPrefix(parsed.Package.Path.String(), "data.")
		modules[i].AST = parsed
	}

	return modules, nil
}

func compileModules(modules []module) (*ast.Compiler, error) {
	parsed := make(map[string]*ast.Module, len(modules))
	for _, module := range modules {
		parsed[module.Filename] = module.AST
	}

	compiler := ast.NewCompiler().WithCapabilities(playgroundCapabilities())
	compiler.Compile(parsed)
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	return compiler, nil
}

func collectRuleMetadata(modules []module, pkg string) ([]ruleMetadata, error) {
	parsed := make([]*ast.Module, 0, len(modules))
	for _, module := range modules {
		parsed = append(parsed, module.AST)
	}

	annotations, errs := ast.BuildAnnotationSet(parsed)
	if len(errs) > 0 {
		return nil, errs
	}

	var rules []ruleMetadata
	for _, module := range modules {
		if module.Package != pkg {
			continue
		}

		for _, astRule := range module.AST.Rules {
			ruleName := astRule.Head.Name.String()
			kind, ok := classifyRule(ruleName)
			if !ok {
				continue
			}

			rules = append(rules, ruleMetadata{
				RuleName: ruleName,
				Kind:     kind,
				Info:     ruleInfo(annotations, astRule),
			})
		}
	}
	return rules, nil
}

func classifyRule(ruleName string) (ruleKind, bool) {
	switch {
	case failureRulePattern.MatchString(ruleName):
		return failure, true
	case warningRulePattern.MatchString(ruleName):
		return warning, true
	default:
		return "", false
	}
}

func ruleInfo(annotations *ast.AnnotationSet, astRule *ast.Rule) rule.Info {
	if annotations == nil {
		return rule.Info{}
	}
	for _, ref := range annotations.Chain(astRule) {
		if ref.GetRule() == nil || ref.Annotations == nil {
			continue
		}
		return rule.RuleInfo(ref)
	}
	return rule.Info{}
}

func uniqueRuleNames(rules []ruleMetadata) []string {
	seen := map[string]bool{}
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		if seen[rule.RuleName] {
			continue
		}
		seen[rule.RuleName] = true
		names = append(names, rule.RuleName)
	}
	return names
}

func evalRule(ctx context.Context, compiler *ast.Compiler, data map[string]any, input any, pkg string, ruleName string) ([]Result, error) {
	query := fmt.Sprintf("data.%s.%s", pkg, ruleName)
	printHook := opaPrintHook{s: &[]string{}}
	opts := []func(*rego.Rego){
		rego.Compiler(compiler),
		rego.Input(input),
		rego.Query(query),
		rego.Store(inmem.NewFromObject(data)),
		rego.Capabilities(playgroundCapabilities()),
		rego.PrintHook(printHook),
	}

	resultSet, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(resultSet))
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			expressionValues, ok := expression.Value.([]any)
			if !ok || len(expressionValues) == 0 {
				continue
			}
			for _, value := range expressionValues {
				results = appendValue(results, value)
			}
		}
	}

	if len(*printHook.s) > 0 && len(results) > 0 {
		results[len(results)-1].Outputs = append(results[len(results)-1].Outputs, *printHook.s...)
	}
	return results, nil
}

func appendValue(results []Result, value any) []Result {
	switch value := value.(type) {
	case nil:
		return results
	case string:
		return append(results, Result{
			Message:  value,
			Metadata: map[string]any{},
		})
	case bool:
		if value {
			return append(results, Result{Metadata: map[string]any{}})
		}
	case []any:
		for _, item := range value {
			results = appendValue(results, item)
		}
	case map[string]any:
		results = append(results, resultFromObject(value))
	default:
		results = append(results, Result{
			Message:  fmt.Sprintf("unexpected policy result type %T: %v", value, value),
			Metadata: map[string]any{},
		})
	}
	return results
}

func resultFromObject(value map[string]any) Result {
	msg, _ := value["msg"].(string)
	metadata := make(map[string]any, len(value))
	for key, item := range value {
		if key != "msg" {
			metadata[key] = item
		}
	}
	return Result{
		Message:  msg,
		Metadata: metadata,
	}
}

func metadataForResult(result Result, rules []ruleMetadata, ruleName string) ruleMetadata {
	if code, ok := result.Metadata[metadataCode].(string); ok {
		for _, metadata := range rules {
			if metadata.Info.Code == code {
				return metadata
			}
		}
	}

	for _, metadata := range rules {
		if metadata.RuleName == ruleName {
			return metadata
		}
	}
	return ruleMetadata{}
}

func addRuleMetadata(result *Result, rule rule.Info) {
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	if rule.Code != "" {
		result.Metadata[metadataCode] = rule.Code
	}
	if rule.Title != "" {
		result.Metadata[metadataTitle] = rule.Title
	}
	if rule.Description != "" {
		result.Metadata[metadataDescription] = rule.Description
	}
	if rule.Solution != "" {
		result.Metadata[metadataSolution] = rule.Solution
	}
	if rule.Severity != "" {
		result.Metadata[metadataSeverity] = rule.Severity
	}
	if rule.EffectiveOn != "" {
		result.Metadata[metadataEffectiveOn] = rule.EffectiveOn
	}
	if len(rule.Collections) > 0 {
		result.Metadata[metadataCollections] = rule.Collections
	}
	if len(rule.DependsOn) > 0 {
		result.Metadata[metadataDependsOn] = rule.DependsOn
	}
}

func successes(rules []ruleMetadata, violations []Result, warnings []Result) []Result {
	seen := map[string]bool{}
	for _, result := range append(append([]Result{}, violations...), warnings...) {
		if result.ruleName != "" {
			seen[result.ruleName] = true
		}
		if code, ok := result.Metadata[metadataCode].(string); ok {
			seen[code] = true
		}
	}

	var results []Result
	for _, metadata := range rules {
		code := metadata.Info.Code
		if code == "" {
			code = metadata.RuleName
		}
		if seen[code] {
			continue
		}

		result := Result{
			Message:  "Pass",
			Metadata: map[string]any{},
		}
		addRuleMetadata(&result, metadata.Info)
		if result.Metadata[metadataCode] == nil {
			result.Metadata[metadataCode] = code
		}
		results = append(results, result)
	}
	return results
}

func playgroundCapabilities() *ast.Capabilities {
	capabilities := ast.CapabilitiesForThisVersion()
	capabilities.AllowNet = []string{}

	builtins := make([]*ast.Builtin, 0, len(capabilities.Builtins))
	for _, builtin := range capabilities.Builtins {
		if !disallowedBuiltins[builtin.Name] {
			builtins = append(builtins, builtin)
		}
	}
	capabilities.Builtins = builtins
	return capabilities
}

// MarshalResponse renders the playground response in the same stable format the
// browser bridge needs.
func MarshalResponse(response Response) string {
	out, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fallback, _ := json.Marshal(map[string]string{
			"error": err.Error(),
		})
		return string(fallback)
	}
	return string(out)
}

type opaPrintHook struct {
	s *[]string
}

func (ph opaPrintHook) Print(pctx print.Context, msg string) error {
	buf := new(bytes.Buffer)
	if pctx.Location != nil {
		_, _ = fmt.Fprintf(buf, "%v: ", pctx.Location)
	}
	_, _ = buf.WriteString(msg)
	*ph.s = append(*ph.s, buf.String())
	return nil
}

var _ print.Hook = opaPrintHook{}
