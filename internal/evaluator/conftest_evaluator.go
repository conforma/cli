// Copyright 2022 Red Hat, Inc.
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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/ast"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/enterprise-contract/ec-cli/internal/opa"
	"github.com/enterprise-contract/ec-cli/internal/opa/rule"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

type contextKey string

const (
	runnerKey        contextKey = "ec.evaluator.runner"
	capabilitiesKey  contextKey = "ec.evaluator.capabilities"
	effectiveTimeKey contextKey = "ec.evaluator.effective_time"
)

type CheckResult struct {
	output.CheckResult
	Successes []output.Result `json:"successes,omitempty"`
}

type CheckResults []CheckResult

func (c CheckResults) ToConftestResults() []output.CheckResult {
	results := make([]output.CheckResult, 0, len(c))

	for _, r := range c {
		results = append(results, r.CheckResult)
	}

	return results
}

type testRunner interface {
	Run(context.Context, []string) ([]output.CheckResult, error)
}

const (
	effectiveOnFormat   = "2006-01-02T15:04:05Z"
	effectiveOnTimeout  = -90 * 24 * time.Hour // keep effective_on metadata up to 90 days
	metadataCode        = "code"
	metadataCollections = "collections"
	metadataDescription = "description"
	metadataEffectiveOn = "effective_on"
	metadataSolution    = "solution"
	metadataTerm        = "term"
	metadataTitle       = "title"
)

// ConftestEvaluator represents a structure which can be used to evaluate targets
type conftestEvaluator struct {
	policySources []source.PolicySource
	outputFormat  string
	workDir       string
	dataDir       string
	policyDir     string
	policy        policy.Policy
	fs            afero.Fs
	namespace     []string
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p policy.Policy) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespace(ctx, policySources, p, nil)

}

// set the policy namespace
func NewConftestEvaluatorWithNamespace(ctx context.Context, policySources []source.PolicySource, p policy.Policy, namespace []string) (Evaluator, error) {
	fs := utils.FS(ctx)
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
		namespace:     namespace,
	}

	dir, err := utils.CreateWorkDir(fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir

	c.policyDir = filepath.Join(c.workDir, "policy")
	c.dataDir = filepath.Join(c.workDir, "data")

	log.Debugf("Created work dir %s", dir)

	if err := c.createDataDirectory(ctx); err != nil {
		return nil, err
	}

	if err := c.createCapabilitiesFile(ctx); err != nil {
		return nil, err
	}

	log.Debug("Conftest test runner created")
	return c, nil
}

// Destroy removes the working directory
func (c conftestEvaluator) Destroy() {
	if os.Getenv("EC_DEBUG") == "" {
		_ = c.fs.RemoveAll(c.workDir)
	}
}

func (c conftestEvaluator) CapabilitiesPath() string {
	return path.Join(c.workDir, "capabilities.json")
}

type policyRules map[string]rule.Info

func (r *policyRules) collect(a *ast.AnnotationsRef) {
	if a.Annotations == nil {
		return
	}

	info := rule.RuleInfo(a)

	if info.ShortName == "" {
		// no short name matching with the code from Metadata will not be
		// deterministic
		return
	}

	code := info.Code
	(*r)[code] = info
}

func (c conftestEvaluator) Evaluate(ctx context.Context, inputs []string) (CheckResults, error) {
	results := make([]CheckResult, 0, 10)

	// hold all rule annotations
	rules := policyRules{}
	// Download all sources
	for _, s := range c.policySources {
		dir, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}

		fs := utils.FS(ctx)
		annotations, err := opa.InspectDir(fs, dir)
		if err != nil {
			return nil, err
		}

		for _, a := range annotations {
			if a.Annotations == nil {
				continue
			}
			rules.collect(a)
		}
	}

	var r testRunner
	var ok bool
	if r, ok = ctx.Value(runnerKey).(testRunner); r == nil || !ok {

		// should there be a namespace defined or not
		allNamespaces := true
		if len(c.namespace) > 0 {
			allNamespaces = false
		}

		r = &runner.TestRunner{
			Data:          []string{c.dataDir},
			Policy:        []string{c.policyDir},
			Namespace:     c.namespace,
			AllNamespaces: allNamespaces,
			NoFail:        true,
			Output:        c.outputFormat,
			Capabilities:  c.CapabilitiesPath(),
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", inputs)

	runResults, err := r.Run(ctx, inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, err
	}

	effectiveTime := c.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	// loop over each policy (namespace) evaluation
	// effectively replacing the results returned from conftest
	ruleCollection := make(map[string]bool)
	for i, result := range runResults {
		log.Debugf("Evaluation result at %d: %#v", i, result)
		warnings := []output.Result{}
		failures := []output.Result{}
		exceptions := []output.Result{}
		skipped := []output.Result{}

		for i := range result.Warnings {
			warning := result.Warnings[i]
			r, ok := addRuleMetadata(ctx, &warning, rules)
			ruleCollection[r] = ok

			if !c.isResultIncluded(warning) {
				log.Debugf("Skipping result warning: %#v", warning)
				continue
			}
			warnings = append(warnings, warning)
		}

		for i := range result.Failures {
			failure := result.Failures[i]
			r, ok := addRuleMetadata(ctx, &failure, rules)
			ruleCollection[r] = ok

			if !c.isResultIncluded(failure) {
				log.Debugf("Skipping result failure: %#v", failure)
				continue
			}

			if !isResultEffective(failure, effectiveTime) {
				// TODO: Instead of moving to warnings, create new attribute: "futureViolations"
				warnings = append(warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}

		for i := range result.Exceptions {
			exception := result.Exceptions[i]
			r, ok := addRuleMetadata(ctx, &exception, rules)
			ruleCollection[r] = ok
			exceptions = append(exceptions, exception)
		}

		for i := range result.Skipped {
			skip := result.Skipped[i]
			r, ok := addRuleMetadata(ctx, &skip, rules)
			ruleCollection[r] = ok
			skipped = append(skipped, skip)
		}

		result.Warnings = warnings
		result.Failures = failures
		result.Exceptions = exceptions
		result.Skipped = skipped

		results = append(results, CheckResult{CheckResult: result})
	}

	// set successes, these are not provided in the Conftest results, so we
	// reconstruct these from the parsed rules, any rule that hasn't been
	// touched by adding metadata must have succeeded

	// TODO see about multiple results, somehow; using results[0] for now
	if l := len(rules); l > 0 {
		results[0].Successes = make([]output.Result, 0, l)
	}

	// any rule left DID NOT get metadata added so it's a success
	// this depends on the delete in addMetadata
	for code, rule := range rules {
		if ruleCode, ok := ruleCollection[code]; ruleCode && ok {
			continue
		}

		result := output.Result{
			Message: "Pass",
			Metadata: map[string]interface{}{
				"code": code,
			},
		}

		if rule.Title != "" {
			result.Metadata["title"] = rule.Title
		}

		if rule.Description != "" {
			result.Metadata["description"] = rule.Description
		}

		if len(rule.Collections) > 0 {
			result.Metadata["collections"] = rule.Collections
		}

		if !c.isResultIncluded(result) {
			log.Debugf("Skipping result success: %#v", result)
			continue
		}

		if rule.EffectiveOn != "" {
			result.Metadata[metadataEffectiveOn] = rule.EffectiveOn
		}

		// Let's omit the solution text here because if the rule is passing
		// already then the user probably doesn't care about the solution.

		if !isResultEffective(result, effectiveTime) {
			log.Debugf("Skipping result success: %#v", result)
			continue
		}

		// Todo maybe: We could also call isResultEffective here for the
		// success and skip it if the rule is not yet effective. This would
		// require collecting the effective_on value from the custom annotation
		// in rule.RuleInfo.

		results[0].Successes = append(results[0].Successes, result)
	}

	// Evaluate total successes, warnings, and failures. If all are 0, then
	// we have effectively failed, because no tests were actually ran due to
	// input error, etc.
	var total int

	for _, res := range results {
		// we could use len(res.Successes), but that is not correct as some of
		// the successes might not follow the conventions used, i.e. have
		// short_name annotation, so we use the number calculated by Conftest
		total += res.CheckResult.Successes
		total += len(res.Warnings)
		total += len(res.Failures)
	}
	if total == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, nil
}

func addRuleMetadata(ctx context.Context, result *output.Result, rules policyRules) (string, bool) {
	code, ok := (*result).Metadata[metadataCode].(string)
	if ok {
		addMetadataToResults(ctx, result, rules[code])
		return code, true
	}
	return "", false
}

func addMetadataToResults(ctx context.Context, r *output.Result, rule rule.Info) {
	// Note that r.Metadata already includes some fields that we get from
	// the real conftest violation and warning results, (as provided by
	// lib.result_helper in the ec-policies rego). Here we augment it with
	// other fields from rule.Metadata, which we get by opa-inspecting the
	// rego source.

	if r.Metadata == nil {
		return
	}
	// normalize collection to []string
	if v, ok := r.Metadata[metadataCollections]; ok {
		switch vals := v.(type) {
		case []any:
			col := make([]string, 0, len(vals))
			for _, c := range vals {
				col = append(col, fmt.Sprint(c))
			}
			r.Metadata[metadataCollections] = col
		case []string:
			// all good, mainly left for documentation of the normalization
		default:
			// remove unsupported collections attribute
			delete(r.Metadata, metadataCollections)
		}
	}

	if rule.Title != "" {
		r.Metadata[metadataTitle] = rule.Title
	}
	if rule.EffectiveOn != "" {
		r.Metadata[metadataEffectiveOn] = rule.EffectiveOn
	}
	if rule.Description != "" {
		r.Metadata[metadataDescription] = rule.Description
	}
	if rule.Solution != "" {
		r.Metadata[metadataSolution] = rule.Solution
	}
	if len(rule.Collections) > 0 {
		r.Metadata[metadataCollections] = rule.Collections
	}

	// If the rule has been effective for a long time, we'll consider
	// the effective_on date not relevant and not bother including it
	if effectiveTime, ok := ctx.Value(effectiveTimeKey).(time.Time); ok {
		if effectiveOnString, ok := r.Metadata[metadataEffectiveOn].(string); ok {
			effectiveOnTime, err := time.Parse(effectiveOnFormat, effectiveOnString)
			if err == nil {
				if effectiveOnTime.Before(effectiveTime.Add(effectiveOnTimeout)) {
					delete(r.Metadata, metadataEffectiveOn)
				}
			} else {
				log.Warnf("Invalid %q value %q", metadataEffectiveOn, rule.EffectiveOn)
			}
		}
	} else {
		log.Warnf("Could not get effectiveTime from context")
	}
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(ctx context.Context, dataDir string, p policy.Policy) error {
	if p == nil {
		return nil
	}

	configFilePath := filepath.Join(dataDir, "config.json")

	var config = map[string]interface{}{
		"config": map[string]interface{}{},
	}

	pc := &struct {
		WhenNs int64 `json:"when_ns"`
	}{}

	// Now that the future deny logic is handled in the ec-cli and not in rego,
	// this field is used only for the checking the effective times in the
	// acceptable bundles list. Always set it, even when we are using the current
	// time, so that a consistent current time is used everywhere.
	pc.WhenNs = p.EffectiveTime().UnixNano()

	// Add the policy config we just prepared
	config["config"] = map[string]interface{}{
		"policy": pc,
	}

	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}

	fs := utils.FS(ctx)
	// Check to see if the data.json file exists
	exists, err := afero.Exists(fs, configFilePath)
	if err != nil {
		return err
	}
	// if so, remove it
	if exists {
		if err := fs.Remove(configFilePath); err != nil {
			return err
		}
	}
	// write our jsonData content to the data.json file in the data directory under the workDir
	log.Debugf("Writing config data to %s: %#v", configFilePath, string(configJSON))
	if err := afero.WriteFile(fs, configFilePath, configJSON, 0444); err != nil {
		return err
	}

	return nil
}

// createDataDirectory creates the base content in the data directory
func (c *conftestEvaluator) createDataDirectory(ctx context.Context) error {
	fs := utils.FS(ctx)
	dataDir := c.dataDir
	exists, err := afero.DirExists(fs, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = fs.MkdirAll(dataDir, 0755)
	}

	if err := createConfigJSON(ctx, dataDir, c.policy); err != nil {
		return err
	}

	return nil
}

// createCapabilitiesFile writes the default OPA capabilities a file.
func (c *conftestEvaluator) createCapabilitiesFile(ctx context.Context) error {
	fs := utils.FS(ctx)
	f, err := fs.Create(c.CapabilitiesPath())
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := strictCapabilities(ctx)
	if err != nil {
		return err
	}

	if _, err := f.WriteString(data); err != nil {
		return err
	}
	log.Debugf("Capabilities file written to %s", f.Name())

	return nil
}

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure output.Result, now time.Time) bool {
	raw, ok := failure.Metadata[metadataEffectiveOn]
	if !ok {
		return true
	}
	str, ok := raw.(string)
	if !ok {
		log.Warnf("Ignoring non-string %q value %#v", metadataEffectiveOn, raw)
		return true
	}
	effectiveOn, err := time.Parse(effectiveOnFormat, str)
	if err != nil {
		log.Warnf("Invalid %q value %q", metadataEffectiveOn, failure.Metadata)
		return true
	}
	return effectiveOn.Before(now)
}

// isResultIncluded returns whether or not the result should be included or
// discarded based on the policy configuration.
func (c conftestEvaluator) isResultIncluded(result output.Result) bool {
	ruleMatchers := makeMatchers(result)
	var includes, excludes []string

	spec := c.policy.Spec()
	cfg := spec.Configuration
	if cfg != nil {
		for _, c := range cfg.Collections {
			// If the old way of specifying collections are used, convert them.
			includes = append(includes, "@"+c)
		}
		includes = append(includes, cfg.Include...)
		excludes = append(excludes, cfg.Exclude...)
	}

	if len(includes) == 0 {
		includes = []string{"*"}
	}

	includeScore := scoreMatches(ruleMatchers, includes)
	excludeScore := scoreMatches(ruleMatchers, excludes)

	return includeScore > excludeScore
}

// scoreMatches returns the combined score for every match between needles and haystack.
func scoreMatches(needles, haystack []string) int {
	var s int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += score(hay)
			}
		}
	}
	return s
}

// score computes and returns the specificity of the given name. The scoring guidelines are:
//  1. If the name starts with "@" the returned score is exactly 10, e.g. "@collection". No
//     further processing is done.
//  2. Add 1 if the name covers everything, i.e. "*"
//  3. Add 10 if the name specifies a package name, e.g. "pkg", "pkg.", "pkg.*", or "pkg.rule"
//  4. Add 100 if a term is used, e.g. "*:term", "pkg:term" or "pkg.rule:term"
//  5. Add 100 if a rule is used, e.g. "pkg.rule", "pkg.rule:term"
//
// The score is cumulative. If a name is covered by multiple items in the guidelines, they
// are added together. For example, "pkg.rule:term" scores at 210.
func score(name string) int {
	if strings.HasPrefix(name, "@") {
		return 10
	}
	var value int
	shortName, term, _ := strings.Cut(name, ":")
	if term != "" {
		value += 100
	}
	pkg, rule, _ := strings.Cut(shortName, ".")
	if pkg == "*" {
		value += 1
	} else {
		value += 10
	}
	if rule != "*" && rule != "" {
		value += 100
	}
	return value
}

// makeMatchers returns the possible matching strings for the result.
func makeMatchers(result output.Result) []string {
	code := ExtractStringFromMetadata(result, metadataCode)
	term := ExtractStringFromMetadata(result, metadataTerm)
	parts := strings.Split(code, ".")
	var pkg string
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	rule := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, rule))
	}

	// A term can be applied to any of the package matchers above.
	if term != "" {
		for i, l := 0, len(matchers); i < l; i++ {
			matchers = append(matchers, fmt.Sprintf("%s:%s", matchers[i], term))
		}
	}

	matchers = append(matchers, "*")

	matchers = append(matchers, extractCollections(result)...)

	return matchers
}

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result output.Result) []string {
	var collections []string
	if maybeCollections, exists := result.Metadata[metadataCollections]; exists {
		if ruleCollections, ok := maybeCollections.([]string); ok {
			for _, c := range ruleCollections {
				collections = append(collections, "@"+c)
			}
		} else {
			panic(fmt.Sprintf("Unsupported collections set in Metadata, expecting []string got: %v", maybeCollections))
		}
	}
	return collections
}

// ExtractStringFromMetadata returns the string value from the result metadata at the given key.
func ExtractStringFromMetadata(result output.Result, key string) string {
	if maybeValue, exists := result.Metadata[key]; exists {
		if value, ok := maybeValue.(string); ok {
			return value
		}
	}
	return ""
}

func withCapabilities(ctx context.Context, capabilities string) context.Context {
	return context.WithValue(ctx, capabilitiesKey, capabilities)
}

// strictCapabilities returns a JSON serialized OPA Capability meant to isolate rego
// policies from accessing external information, such as hosts or environment
// variables. If the context already contains the capability, then that is
// returned as is. Use withCapabilities to pre-populate the context if needed. The
// strict capabilities aim to provide a safe environment to execute arbitrary
// rego policies.
func strictCapabilities(ctx context.Context) (string, error) {
	if c, ok := ctx.Value(capabilitiesKey).(string); ok && c != "" {
		return c, nil
	}

	capabilities := ast.CapabilitiesForThisVersion()
	// An empty list means no hosts can be reached. However, a nil value means all
	// hosts can be reached. Unfortunately, the required JSON marshalling process
	// drops the "allow_net" attribute if it's an empty list. So when it's loaded
	// by OPA, it's seen as a nil value. As a workaround, we add an empty string
	// to the list which shouldn't match any host but preserves the list after the
	// JSON dance.
	capabilities.AllowNet = []string{""}
	log.Debug("Network access from rego policies disabled")

	builtins := make([]*ast.Builtin, 0, len(capabilities.Builtins))
	disallowed := sets.NewString(
		// disallow access to environment variables
		"opa.runtime",
		// disallow external connections. This is a second layer of defense since
		// AllowNet should prevent external connections in the first place.
		"http.send", "net.lookup_ip_addr",
	)
	for _, b := range capabilities.Builtins {
		if !disallowed.Has(b.Name) {
			builtins = append(builtins, b)
		}
	}
	capabilities.Builtins = builtins
	log.Debugf("Access to some rego built-in functions disabled: %s", disallowed.List())

	blob, err := json.Marshal(capabilities)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}
