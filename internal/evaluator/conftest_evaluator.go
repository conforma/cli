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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime/trace"
	"strings"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/conforma/cli/internal/opa"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/tracing"
	"github.com/conforma/cli/internal/utils"
)

type contextKey string

const (
	runnerKey        contextKey = "ec.evaluator.runner"
	capabilitiesKey  contextKey = "ec.evaluator.capabilities"
	effectiveTimeKey contextKey = "ec.evaluator.effective_time"
)

// trim removes all failure, warning, success or skipped results that depend on
// a result reported as failure, warning or skipped. Dependencies are declared
// by setting the metadata via metadataDependsOn.
func trim(results *[]Outcome) {
	// holds codes for all failures, warnings or skipped rules, as a map to ease
	// the lookup, any rule that depends on a reported code will be removed from
	// the results
	reported := map[string]bool{}

	for _, checks := range *results {
		for _, results := range [][]Result{checks.Failures, checks.Warnings, checks.Skipped} {
			for _, result := range results {
				if code, ok := result.Metadata[metadataCode].(string); ok {
					reported[code] = true
				}
			}
		}
	}

	// helper function inlined for ecapsulation, removes any results that depend
	// on a reported rule, by code
	trimOutput := func(what []Result) []Result {
		if what == nil {
			// nil might get passed in, while this would not cause an issue, the
			// function would return empty array and that would needlessly
			// change the output
			return nil
		}

		// holds leftover results, i.e. the ones that do not depend on a rule
		// reported as failure, warning or skipped
		trimmed := make([]Result, 0, len(what))
		for _, result := range what {
			if dependency, ok := result.Metadata[metadataDependsOn].([]string); ok {
				for _, d := range dependency {
					if !reported[d] {
						trimmed = append(trimmed, result)
					}
				}
			} else {
				trimmed = append(trimmed, result)
			}
		}

		return trimmed
	}

	addNote := func(results []Result) []Result {
		for i := range results {
			var description, code string
			var ok bool
			if description, ok = results[i].Metadata[metadataDescription].(string); !ok {
				continue
			}

			if code, ok = results[i].Metadata[metadataCode].(string); !ok {
				continue
			}

			results[i].Metadata[metadataDescription] = fmt.Sprintf("%s. To exclude this rule add %s to the `exclude` section of the policy configuration.", strings.TrimSuffix(description, "."), excludeDirectives(code, results[i].Metadata[metadataTerm]))
		}

		return results
	}

	for i, checks := range *results {
		(*results)[i].Failures = addNote(trimOutput(checks.Failures))
		(*results)[i].Warnings = trimOutput(checks.Warnings)
		(*results)[i].Skipped = trimOutput(checks.Skipped)
		(*results)[i].Successes = trimOutput(checks.Successes)
	}
}

// Used above to suggest what to exclude to skip a certain violation.
// Use the term if one is provided so it's as specific as possible.
func excludeDirectives(code string, rawTerm any) string {
	output := []string{}

	if term, ok := rawTerm.(string); ok && term != "" {
		// A single term was provided
		output = append(output, fmt.Sprintf(`"%s:%s"`, code, term))
	}

	if rawTerms, ok := rawTerm.([]any); ok {
		// Multiple terms were provided
		for _, t := range rawTerms {
			if term, ok := t.(string); ok && term != "" {
				output = append(output, fmt.Sprintf(`"%s:%s"`, code, term))
			}
		}
	}

	if len(output) == 0 {
		// No terms were provided (or some unexpected edge case)
		output = append(output, fmt.Sprintf(`"%s"`, code))
	}

	prefix := ""
	if len(output) > 1 {
		// For required tasks I think just the first one would be sufficient, but I'm
		// not sure if that's always true, so let's give some slightly vague advice
		prefix = "one or more of "
	}

	// Put it all together and return a string
	return fmt.Sprintf("%s%s", prefix, strings.Join(output, ", "))
}

type testRunner interface {
	Run(context.Context, []string) ([]Outcome, error)
}

const (
	effectiveOnFormat         = "2006-01-02T15:04:05Z"
	effectiveOnTimeout        = -90 * 24 * time.Hour // keep effective_on metadata up to 90 days
	metadataCode              = "code"
	metadataCollections       = "collections"
	metadataDependsOn         = "depends_on"
	metadataDescription       = "description"
	metadataPipelineIntention = "pipeline_intention"
	metadataSeverity          = "severity"
	metadataEffectiveOn       = "effective_on"
	metadataSolution          = "solution"
	metadataTerm              = "term"
	metadataTitle             = "title"
)

const (
	severityWarning = "warning"
	severityFailure = "failure"
)

// ConfigProvider is a subset of the policy.Policy interface. Its purpose is to codify which parts
// of Policy are actually used and to make it easier to use mock in tests.
type ConfigProvider interface {
	EffectiveTime() time.Time
	SigstoreOpts() (policy.SigstoreOpts, error)
	Spec() ecc.EnterpriseContractPolicySpec
}

// ConftestEvaluator represents a structure which can be used to evaluate targets
type conftestEvaluator struct {
	policySources []source.PolicySource
	outputFormat  string
	workDir       string
	dataDir       string
	policyDir     string
	policy        ConfigProvider
	include       *Criteria
	exclude       *Criteria
	fs            afero.Fs
	namespace     []string
}

type conftestRunner struct {
	runner.TestRunner
}

func (r conftestRunner) Run(ctx context.Context, fileList []string) (result []Outcome, err error) {
	r.Trace = tracing.FromContext(ctx).Enabled(tracing.Opa)

	var conftestResult []output.CheckResult
	conftestResult, err = r.TestRunner.Run(ctx, fileList)
	if err != nil {
		return
	}

	for _, res := range conftestResult {
		if log.IsLevelEnabled(log.TraceLevel) {
			for _, q := range res.Queries {
				for _, t := range q.Traces {
					log.Tracef("[%s] %s", q.Query, t)
				}
			}
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			for _, q := range res.Queries {
				for _, o := range q.Outputs {
					log.Debugf("[%s] %s", q.Query, o)
				}
			}
		}

		result = append(result, Outcome{
			FileName:  res.FileName,
			Namespace: res.Namespace,
			// Conftest doesn't give us a list of successes, just a count. Here we turn that count
			// into a placeholder slice of that size to make processing easier later on.
			Successes:  make([]Result, res.Successes),
			Skipped:    toRules(res.Skipped),
			Warnings:   toRules(res.Warnings),
			Failures:   toRules(res.Failures),
			Exceptions: toRules(res.Exceptions),
		})
	}

	// we can't reference the engine from the test runner or from the results so
	// we need to recreate it, this needs to remain the same as in
	// runner.TestRunner's Run function
	var engine *conftest.Engine
	engine, err = conftest.LoadWithData(r.Policy, r.Data, r.Capabilities, r.Strict)
	if err != nil {
		return
	}

	store := engine.Store()

	var txn storage.Transaction
	txn, err = store.NewTransaction(ctx)
	if err != nil {
		return
	}

	ids := []string{} // everything

	var d any
	d, err = store.Read(ctx, txn, ids)
	if err != nil {
		return
	}

	var ok bool
	if _, ok = d.(map[string]any); !ok {
		err = fmt.Errorf("could not retrieve data from the policy engine: Data is: %v", d)
	}

	return
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespace(ctx, policySources, p, source, nil)
}

// set the policy namespace
func NewConftestEvaluatorWithNamespace(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source, namespace []string) (Evaluator, error) {
	if trace.IsEnabled() {
		r := trace.StartRegion(ctx, "ec:conftest-create-evaluator")
		defer r.End()
	}

	fs := utils.FS(ctx)
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
		namespace:     namespace,
	}

	c.include, c.exclude = computeIncludeExclude(source, p)
	dir, err := utils.CreateWorkDir(fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir
	c.policyDir = filepath.Join(c.workDir, "policy")
	c.dataDir = filepath.Join(c.workDir, "data")

	if err := c.createDataDirectory(ctx); err != nil {
		return nil, err
	}

	log.Debugf("Created work dir %s", dir)

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

func (r *policyRules) collect(a *ast.AnnotationsRef) error {
	if a.Annotations == nil {
		return nil
	}

	info := rule.RuleInfo(a)

	if info.ShortName == "" {
		// no short name matching with the code from Metadata will not be
		// deterministic
		return nil
	}

	code := info.Code

	if _, ok := (*r)[code]; ok {
		return fmt.Errorf("found a second rule with the same code: `%s`", code)
	}

	(*r)[code] = info
	return nil
}

func (c conftestEvaluator) Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, error) {
	var results []Outcome

	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:conftest-evaluate")
		defer region.End()
	}

	// hold all rule annotations from all policy sources
	// NOTE: emphasis on _all rules from all sources_; meaning that if two rules
	// exist with the same code in two separate sources the collected rule
	// information is not deterministic
	rules := policyRules{}
	// Download all sources
	for _, s := range c.policySources {
		dir, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}
		annotations := []*ast.AnnotationsRef{}
		fs := utils.FS(ctx)
		// We only want to inspect the directory of policy subdirs, not config or data subdirs.
		if s.Subdir() == "policy" {
			annotations, err = opa.InspectDir(fs, dir)
			if err != nil {
				errMsg := err
				if err.Error() == "no rego files found in policy subdirectory" {
					// Let's try to give some more robust messaging to the user.
					policyURL, err := url.Parse(s.PolicyUrl())
					if err != nil {
						return nil, errMsg
					}
					// Do we have a prefix at the end of the URL path?
					// If not, this means we aren't trying to access a specific file.
					// TODO: Determine if we want to check for a .git suffix as well?
					pos := strings.LastIndex(policyURL.Path, ".")
					if pos == -1 {
						// Are we accessing a GitHub or GitLab URL? If so, are we beginning with 'https' or 'http'?
						if (policyURL.Host == "github.com" || policyURL.Host == "gitlab.com") && (policyURL.Scheme == "https" || policyURL.Scheme == "http") {
							log.Debug("Git Hub or GitLab, http transport, and no file extension, this could be a problem.")
							errMsg = fmt.Errorf("%s.\nYou've specified a %s URL with an %s:// scheme.\nDid you mean: %s instead?", errMsg, policyURL.Hostname(), policyURL.Scheme, fmt.Sprint(policyURL.Host+policyURL.RequestURI()))
						}
					}
				}
				return nil, errMsg
			}
		}

		for _, a := range annotations {
			if a.Annotations == nil {
				continue
			}
			if err := rules.collect(a); err != nil {
				return nil, err
			}
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

		r = &conftestRunner{
			runner.TestRunner{
				Data:          []string{c.dataDir},
				Policy:        []string{c.policyDir},
				Namespace:     c.namespace,
				AllNamespaces: allNamespaces,
				NoFail:        true,
				Output:        c.outputFormat,
				Capabilities:  c.CapabilitiesPath(),
			},
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", target.Inputs)

	runResults, err := r.Run(ctx, target.Inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, err
	}

	effectiveTime := c.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	// Track how many rules have been processed. This is used later on to determine if anything
	// at all was processed.
	totalRules := 0

	// Populate a list with all the include directives specified in the
	// policy config.
	// Each include matching a result will be pruned from the list, so
	// that in the end the list will contain all the unmatched includes.
	missingIncludes := map[string]bool{}
	for _, defaultItem := range c.include.defaultItems {
		missingIncludes[defaultItem] = true
	}
	for _, digestItems := range c.include.digestItems {
		for _, digestItem := range digestItems {
			missingIncludes[digestItem] = true
		}
	}

	// loop over each policy (namespace) evaluation
	// effectively replacing the results returned from conftest
	for i, result := range runResults {
		log.Debugf("Evaluation result at %d: %#v", i, result)
		warnings := []Result{}
		failures := []Result{}
		exceptions := []Result{}
		skipped := []Result{}

		for i := range result.Warnings {
			warning := result.Warnings[i]
			addRuleMetadata(ctx, &warning, rules)

			if !c.isResultIncluded(warning, target.Target, missingIncludes) {
				log.Debugf("Skipping result warning: %#v", warning)
				continue
			}

			if getSeverity(warning) == severityFailure {
				failures = append(failures, warning)
			} else {
				warnings = append(warnings, warning)
			}
		}

		for i := range result.Failures {
			failure := result.Failures[i]
			addRuleMetadata(ctx, &failure, rules)

			if !c.isResultIncluded(failure, target.Target, missingIncludes) {
				log.Debugf("Skipping result failure: %#v", failure)
				continue
			}

			if getSeverity(failure) == severityWarning || !isResultEffective(failure, effectiveTime) {
				warnings = append(warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}

		for i := range result.Exceptions {
			exception := result.Exceptions[i]
			addRuleMetadata(ctx, &exception, rules)
			exceptions = append(exceptions, exception)
		}

		for i := range result.Skipped {
			skip := result.Skipped[i]
			addRuleMetadata(ctx, &skip, rules)
			skipped = append(skipped, skip)
		}

		result.Warnings = warnings
		result.Failures = failures
		result.Exceptions = exceptions
		result.Skipped = skipped

		// Replace the placeholder successes slice with the actual successes.
		result.Successes = c.computeSuccesses(result, rules, target.Target, missingIncludes)

		totalRules += len(result.Warnings) + len(result.Failures) + len(result.Successes)

		results = append(results, result)
	}

	for missingInclude, isMissing := range missingIncludes {
		if isMissing {
			results = append(results, Outcome{
				Warnings: []Result{{
					Message: fmt.Sprintf("Include criterion '%s' doesn't match any policy rule", missingInclude),
				}},
			})
		}
	}

	trim(&results)

	// If no rules were checked, then we have effectively failed, because no tests were actually
	// ran due to input error, etc.
	if totalRules == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, nil
}

func toRules(results []output.Result) []Result {
	var eResults []Result
	for _, r := range results {
		eResults = append(eResults, Result{
			Message:  r.Message,
			Metadata: r.Metadata,
			Outputs:  r.Outputs,
		})
	}

	return eResults
}

// computeSuccesses generates success results, these are not provided in the
// Conftest results, so we reconstruct these from the parsed rules, any rule
// that hasn't been touched by adding metadata must have succeeded
func (c conftestEvaluator) computeSuccesses(
	result Outcome,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
) []Result {
	// what rules, by code, have we seen in the Conftest results, use map to
	// take advantage of hashing for quicker lookup
	seenRules := map[string]bool{}
	for _, o := range [][]Result{result.Failures, result.Warnings, result.Skipped, result.Exceptions} {
		for _, r := range o {
			if code, ok := r.Metadata[metadataCode].(string); ok {
				seenRules[code] = true
			}
		}
	}

	var successes []Result
	if l := len(rules); l > 0 {
		successes = make([]Result, 0, l)
	}

	// any rule left DID NOT get metadata added so it's a success
	// this depends on the delete in addMetadata
	for code, rule := range rules {
		if _, ok := seenRules[code]; ok {
			continue
		}

		// Ignore any successes that are not meant for the package this CheckResult represents
		if rule.Package != result.Namespace {
			continue
		}

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

		if len(rule.PipelineIntention) > 0 {
			success.Metadata[metadataPipelineIntention] = rule.PipelineIntention
		}

		if !c.isResultIncluded(success, target, missingIncludes) {
			log.Debugf("Skipping result success: %#v", success)
			continue
		}

		if rule.EffectiveOn != "" {
			success.Metadata[metadataEffectiveOn] = rule.EffectiveOn
		}

		// Let's omit the solution text here because if the rule is passing
		// already then the user probably doesn't care about the solution.

		successes = append(successes, success)
	}

	return successes
}

func addRuleMetadata(ctx context.Context, result *Result, rules policyRules) {
	code, ok := (*result).Metadata[metadataCode].(string)
	if ok {
		addMetadataToResults(ctx, result, rules[code])
	}
}

func addMetadataToResults(ctx context.Context, r *Result, rule rule.Info) {
	// Note that r.Metadata already includes some fields that we get from
	// the real conftest violation and warning results, (as provided by
	// lib.result_helper in the policy rego). Here we augment it with
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
	if rule.Severity != "" {
		r.Metadata[metadataSeverity] = rule.Severity
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
	if len(rule.DependsOn) > 0 {
		r.Metadata[metadataDependsOn] = rule.DependsOn
	}
	if len(rule.PipelineIntention) > 0 {
		log.Debugf("Evaluator Debug: Adding pipeline_intention %v to rule %s", rule.PipelineIntention, rule.Code)
		r.Metadata[metadataPipelineIntention] = rule.PipelineIntention
	} else {
		log.Debugf("Evaluator Debug: No pipeline_intention for rule %s", rule.Code)
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
func createConfigJSON(ctx context.Context, dataDir string, p ConfigProvider) error {
	if p == nil {
		return nil
	}
	configFilePath := filepath.Join(dataDir, "config.json")

	config := map[string]interface{}{
		"config": map[string]interface{}{},
	}

	pc := &struct {
		WhenNs int64 `json:"when_ns"`
	}{}

	// Now that the future deny logic is handled in the cli and not in rego,
	// this field is used only for the checking the effective times in the
	// acceptable bundles list. Always set it, even when we are using the current
	// time, so that a consistent current time is used everywhere.
	pc.WhenNs = p.EffectiveTime().UnixNano()

	opts, err := p.SigstoreOpts()
	if err != nil {
		return err
	}

	// Add the policy config we just prepared
	config["config"] = map[string]interface{}{
		"policy":                pc,
		"default_sigstore_opts": opts,
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

func getSeverity(r Result) string {
	raw, found := r.Metadata[metadataSeverity]
	if !found {
		return ""
	}
	severity, ok := raw.(string)
	if !ok {
		log.Warnf("Ignoring non-string %q value %#v", metadataSeverity, raw)
		return ""
	}

	switch severity {
	case severityFailure, severityWarning:
		return severity
	default:
		log.Warnf("Ignoring unexpected %q value %s", metadataSeverity, severity)
		return ""
	}
}

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure Result, now time.Time) bool {
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
// 'missingIncludes' is a list of include directives that gets pruned if the result is matched
func (c conftestEvaluator) isResultIncluded(result Result, target string, missingIncludes map[string]bool) bool {
	ruleMatchers := makeMatchers(result)
	includeScore := scoreMatches(ruleMatchers, c.include.get(target), missingIncludes)
	excludeScore := scoreMatches(ruleMatchers, c.exclude.get(target), map[string]bool{})
	return includeScore > excludeScore
}

// scoreMatches returns the combined score for every match between needles and haystack.
// 'toBePruned' contains items that will be removed (pruned) from this map if a match is found.
func scoreMatches(needles, haystack []string, toBePruned map[string]bool) int {
	var s int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += score(hay)
				delete(toBePruned, hay)
			}
		}
	}
	return s
}

// score computes and returns the specificity of the given name. The scoring guidelines are:
//  1. If the name starts with "@" the returned score is exactly 10, e.g. "@collection". No
//     further processing is done.
//  2. Add 1 if the name covers everything, i.e. "*"
//  3. Add 10 if the name specifies a package name, e.g. "pkg", "pkg.", "pkg.*", or "pkg.rule",
//     and an additional 10 based on the namespace depth of the pkg, e.g. "a.pkg.rule" adds 10
//     more, "a.b.pkg.rule" adds 20, etc
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
	nameSplit := strings.Split(shortName, ".")
	nameSplitLen := len(nameSplit)

	if nameSplitLen == 1 {
		// When there are no dots we assume the name refers to a
		// package and any rule inside the package is matched
		if shortName == "*" {
			value += 1
		} else {
			value += 10
		}
	} else if nameSplitLen > 1 {
		// When there is at least one dot we assume the last element
		// is the rule and everything else is the package path
		rule := nameSplit[nameSplitLen-1]
		pkg := strings.Join(nameSplit[:nameSplitLen-1], ".")

		if pkg == "*" {
			// E.g. "*.rule", a weird edge case
			value += 1
		} else {
			// E.g. "pkg.rule" or "path.pkg.rule"
			value += 10 * (nameSplitLen - 1)
		}

		if rule != "*" && rule != "" {
			// E.g. "pkg.rule" so a specific rule was specified
			value += 100
		}

	}
	return value
}

// makeMatchers returns the possible matching strings for the result.
func makeMatchers(result Result) []string {
	code := ExtractStringFromMetadata(result, metadataCode)
	terms := extractStringsFromMetadata(result, metadataTerm)
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

	// A term can be applied to any of the package matchers above. But we don't want to apply a term
	// matcher to a matcher that already includes a term.
	var termMatchers []string
	for _, term := range terms {
		if len(term) == 0 {
			continue
		}
		for _, matcher := range matchers {
			termMatchers = append(termMatchers, fmt.Sprintf("%s:%s", matcher, term))
		}
	}
	matchers = append(matchers, termMatchers...)

	matchers = append(matchers, "*")

	matchers = append(matchers, extractCollections(result)...)

	return matchers
}

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result Result) []string {
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
func ExtractStringFromMetadata(result Result, key string) string {
	values := extractStringsFromMetadata(result, key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func extractStringsFromMetadata(result Result, key string) []string {
	if value, ok := result.Metadata[key].(string); ok && len(value) > 0 {
		return []string{value}
	}
	if anyValues, ok := result.Metadata[key].([]any); ok {
		var values []string
		for _, anyValue := range anyValues {
			if value, ok := anyValue.(string); ok && len(value) > 0 {
				values = append(values, value)
			}
		}
		return values
	}
	return []string{}
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
