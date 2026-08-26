// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"strings"
	"sync"

	ecc "github.com/conforma/crds/api/v1alpha1"
	conftestParser "github.com/open-policy-agent/conftest/parser"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/tracing"
	"github.com/conforma/cli/internal/utils"
)

type opaEvaluator struct {
	basePolicyEvaluator

	engine   *conftest.Engine
	opaTrace bool
	initOnce *sync.Once
	initErr  error
}

func NewOPAEvaluator(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, src ecc.Source, namespace []string) (Evaluator, error) {
	if trace.IsEnabled() {
		r := trace.StartRegion(ctx, "ec:opa-create-evaluator")
		defer r.End()
	}

	o := &opaEvaluator{
		basePolicyEvaluator: basePolicyEvaluator{
			policySources: policySources,
			policy:        p,
			fs:            utils.FS(ctx),
			namespace:     namespace,
			source:        src,
		},
	}

	o.initPolicyResolver(src, p)

	if err := o.initWorkDir(ctx); err != nil {
		return nil, err
	}

	o.initOnce = &sync.Once{}

	log.Debug("OPA evaluator created")
	return o, nil
}

func (o *opaEvaluator) compileEngine(ctx context.Context) error {
	dataDirs, err := o.prepareDataDirs(ctx)
	if err != nil {
		return err
	}

	capabilities, err := conftest.LoadCapabilities(o.CapabilitiesPath())
	if err != nil {
		return fmt.Errorf("load capabilities: %w", err)
	}

	opts := conftest.CompilerOptions{
		RegoVersion:  "v1",
		Capabilities: capabilities,
	}

	engine, err := conftest.LoadWithData([]string{o.policyDir}, dataDirs, opts)
	if err != nil {
		return wrapRegoError(fmt.Errorf("load: %w", err))
	}

	engine.EnableInterQueryCache()
	o.opaTrace = tracing.FromContext(ctx).Enabled(tracing.Opa)
	if o.opaTrace {
		engine.EnableTracing()
	}

	o.engine = engine
	return nil
}

func (o *opaEvaluator) ensureInitialized(ctx context.Context) error {
	o.initOnce.Do(func() {
		if err := o.downloadAndInspectPolicies(ctx); err != nil {
			o.initErr = err
			return
		}
		if err := o.compileEngine(ctx); err != nil {
			o.initErr = err
		}
	})
	return o.initErr
}

func (o *opaEvaluator) Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:opa-evaluate")
		defer region.End()
	}

	if err := o.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	if o.engine == nil {
		return nil, fmt.Errorf("OPA engine not compiled; ensure policies are on the real filesystem")
	}

	filteredNamespaces := o.resolveFilteredNamespaces(target)

	runResults, err := o.evaluateWithEngine(ctx, target, filteredNamespaces)
	if err != nil {
		return nil, err
	}

	return o.postProcessResults(ctx, runResults, target)
}

func (o *opaEvaluator) evaluateWithEngine(ctx context.Context, target EvaluationTarget, filteredNamespaces []string) ([]Outcome, error) {
	namespacesToUse := o.namespace
	if len(filteredNamespaces) > 0 {
		namespacesToUse = filteredNamespaces
	} else if len(namespacesToUse) == 0 {
		namespacesToUse = o.engine.Namespaces()
	}

	log.Debugf("Engine namespaces to use: %v", namespacesToUse)

	var configs map[string]any
	if target.ParsedInput != nil {
		configs = map[string]any{"": target.ParsedInput}
	} else {
		var err error
		configs, err = opaParseInputFiles(target.Inputs)
		if err != nil {
			return nil, fmt.Errorf("parse inputs: %w", err)
		}
	}

	var results []Outcome
	for _, ns := range namespacesToUse {
		for filePath, config := range configs {
			if subconfigs, ok := config.([]any); ok {
				outcome := Outcome{FileName: filePath, Namespace: ns}
				for _, subconfig := range subconfigs {
					sub, err := o.queryNamespace(ctx, filePath, subconfig, ns)
					if err != nil {
						return nil, err
					}
					outcome.Successes = append(outcome.Successes, sub.Successes...)
					outcome.Failures = append(outcome.Failures, sub.Failures...)
					outcome.Warnings = append(outcome.Warnings, sub.Warnings...)
					outcome.Exceptions = append(outcome.Exceptions, sub.Exceptions...)
				}
				results = append(results, outcome)
			} else {
				outcome, err := o.queryNamespace(ctx, filePath, config, ns)
				if err != nil {
					return nil, err
				}
				results = append(results, outcome)
			}
		}
	}
	return results, nil
}

func opaParseInputFiles(inputs []string) (map[string]any, error) {
	var files []string
	for _, input := range inputs {
		info, err := os.Stat(input)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			entries, err := os.ReadDir(input)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					files = append(files, filepath.Join(input, entry.Name()))
				}
			}
		} else {
			files = append(files, input)
		}
	}
	return conftestParser.ParseConfigurations(files)
}

var (
	opaFailureRx = regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
	opaWarningRx = regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
)

func isOPAFailure(name string) bool { return opaFailureRx.MatchString(name) }
func isOPAWarning(name string) bool { return opaWarningRx.MatchString(name) }

func stripRulePrefix(name string) string {
	if name == "violation" || name == "deny" || name == "warn" {
		return ""
	}
	name = strings.TrimPrefix(name, "violation_")
	name = strings.TrimPrefix(name, "deny_")
	name = strings.TrimPrefix(name, "warn_")
	return name
}

func (o *opaEvaluator) queryNamespace(ctx context.Context, fileName string, input any, namespace string) (Outcome, error) {
	outcome := Outcome{
		FileName:  fileName,
		Namespace: namespace,
	}

	ruleNames := o.collectRuleNames(namespace)

	var successes int
	for _, ruleName := range ruleNames {
		ruleResult, err := o.evaluateRule(ctx, input, namespace, ruleName)
		if err != nil {
			return Outcome{}, err
		}
		successes += ruleResult.successes
		outcome.Failures = append(outcome.Failures, ruleResult.failures...)
		outcome.Warnings = append(outcome.Warnings, ruleResult.warnings...)
		outcome.Exceptions = append(outcome.Exceptions, ruleResult.exceptions...)
	}

	resultCount := len(outcome.Failures) + len(outcome.Warnings) + len(outcome.Exceptions) + successes
	if resultCount < len(ruleNames) {
		successes += len(ruleNames) - resultCount
	}
	outcome.Successes = make([]Result, successes)

	return outcome, nil
}

func (o *opaEvaluator) collectRuleNames(namespace string) []string {
	var ruleNames []string
	for _, module := range o.engine.Modules() {
		ns := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		if ns != namespace {
			continue
		}
		for _, r := range module.Rules {
			name := r.Head.Name.String()
			if !isOPAFailure(name) && !isOPAWarning(name) {
				continue
			}
			found := false
			for _, existing := range ruleNames {
				if existing == name {
					found = true
					break
				}
			}
			if !found {
				ruleNames = append(ruleNames, name)
			}
		}
	}
	return ruleNames
}

type ruleEvalResult struct {
	failures   []Result
	warnings   []Result
	exceptions []Result
	successes  int
}

func (o *opaEvaluator) evaluateRule(ctx context.Context, input any, namespace string, ruleName string) (ruleEvalResult, error) {
	var result ruleEvalResult

	exceptionQuery := fmt.Sprintf("data.%s.exception[_][_] == %q", namespace, stripRulePrefix(ruleName))
	exceptionResults, err := o.evalOPAQuery(ctx, input, exceptionQuery)
	if err != nil {
		return result, fmt.Errorf("query exception: %w", err)
	}

	for _, er := range exceptionResults {
		if er.Message == "" {
			result.exceptions = append(result.exceptions, Result{Message: exceptionQuery})
		}
	}

	ruleQuery := fmt.Sprintf("data.%s.%s", namespace, ruleName)
	ruleResults, err := o.evalOPAQuery(ctx, input, ruleQuery)
	if err != nil {
		return result, fmt.Errorf("query rule: %w", err)
	}

	for _, rr := range ruleResults {
		if len(result.exceptions) > 0 {
			// log the exception query as skipped
			log.Debugf("exception query %s skipped", exceptionQuery)
			continue
		}
		if rr.Message == "" {
			result.successes++
			continue
		}
		if isOPAFailure(ruleName) {
			result.failures = append(result.failures, rr)
		} else {
			result.warnings = append(result.warnings, rr)
		}
	}

	return result, nil
}

func (o *opaEvaluator) evalOPAQuery(ctx context.Context, input any, query string) ([]Result, error) {
	ph := opaPrintHook{s: &[]string{}}
	options := []func(r *rego.Rego){
		rego.Input(input),
		rego.Query(query),
		rego.Compiler(o.engine.Compiler()),
		rego.Store(o.engine.Store()),
		rego.Trace(o.opaTrace),
		rego.PrintHook(ph),
	}

	regoInstance := rego.New(options...)
	resultSet, err := regoInstance.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}

	if o.opaTrace && log.IsLevelEnabled(log.TraceLevel) {
		buf := new(bytes.Buffer)
		rego.PrintTrace(buf, regoInstance)
		for _, line := range strings.Split(buf.String(), "\n") {
			if len(line) > 0 {
				log.Tracef("[%s] %s", query, line)
			}
		}
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		for _, out := range *ph.s {
			log.Debugf("[%s] %s", query, out)
		}
	}

	var results []Result
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			expressionValues, ok := expression.Value.([]any)
			if !ok || len(expressionValues) == 0 {
				results = append(results, Result{})
				continue
			}
			for _, v := range expressionValues {
				switch val := v.(type) {
				case string:
					results = append(results, Result{
						Message:  val,
						Metadata: map[string]any{},
					})
				case map[string]any:
					msg, _ := val["msg"].(string)
					metadata := make(map[string]any)
					for k, v := range val {
						if k != "msg" {
							metadata[k] = v
						}
					}
					results = append(results, Result{
						Message:  msg,
						Metadata: metadata,
					})
				default:
					results = append(results, Result{
						Message:  fmt.Sprintf("unexpected policy result type %T: %v", v, v),
						Metadata: map[string]any{},
					})
				}
			}
		}
	}

	return results, nil
}

type opaPrintHook struct {
	s *[]string
}

func (ph opaPrintHook) Print(pctx print.Context, msg string) error {
	*ph.s = append(*ph.s, fmt.Sprintf("%v: %s", pctx.Location, msg))
	return nil
}
