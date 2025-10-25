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
	"os"
	"path"
	"path/filepath"
	"runtime/trace"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/open-policy-agent/conftest/output"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/conftest/runner"
	"github.com/open-policy-agent/opa/v1/ast"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"

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
	reported := collectReportedCodes(*results)

	for i, checks := range *results {
		(*results)[i].Failures = addExclusionNotes(trimOutput(checks.Failures, reported))
		(*results)[i].Warnings = trimOutput(checks.Warnings, reported)
		(*results)[i].Skipped = trimOutput(checks.Skipped, reported)
		(*results)[i].Successes = trimOutput(checks.Successes, reported)
	}
}

// collectReportedCodes collects all reported rule codes from failures, warnings, and skipped results
func collectReportedCodes(results []Outcome) map[string]bool {
	reported := map[string]bool{}

	for _, checks := range results {
		for _, resultList := range [][]Result{checks.Failures, checks.Warnings, checks.Skipped} {
			for _, result := range resultList {
				if code, ok := result.Metadata[metadataCode].(string); ok {
					reported[code] = true
				}
			}
		}
	}

	return reported
}

// trimOutput removes results that depend on reported rules
func trimOutput(what []Result, reported map[string]bool) []Result {
	if what == nil {
		return nil
	}

	trimmed := make([]Result, 0, len(what))
	for _, result := range what {
		if shouldKeepResult(result, reported) {
			trimmed = append(trimmed, result)
		}
	}

	return trimmed
}

// shouldKeepResult determines if a result should be kept based on its dependencies
func shouldKeepResult(result Result, reported map[string]bool) bool {
	dependency, ok := result.Metadata[metadataDependsOn].([]string)
	if !ok {
		return true // No dependencies, keep the result
	}

	// Keep if any dependency is not reported
	for _, d := range dependency {
		if !reported[d] {
			return true
		}
	}

	return false // All dependencies are reported, remove the result
}

// addExclusionNotes adds exclusion notes to failure results
func addExclusionNotes(results []Result) []Result {
	for i := range results {
		description, ok := results[i].Metadata[metadataDescription].(string)
		if !ok {
			continue
		}

		code, ok := results[i].Metadata[metadataCode].(string)
		if !ok {
			continue
		}

		results[i].Metadata[metadataDescription] = fmt.Sprintf("%s. To exclude this rule add %s to the `exclude` section of the policy configuration.", strings.TrimSuffix(description, "."), excludeDirectives(code, results[i].Metadata[metadataTerm]))
	}

	return results
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
	effectiveOnFormat   = "2006-01-02T15:04:05Z"
	effectiveOnTimeout  = -90 * 24 * time.Hour // keep effective_on metadata up to 90 days
	metadataQuery       = "query"
	metadataCode        = "code"
	metadataCollections = "collections"
	metadataDependsOn   = "depends_on"
	metadataDescription = "description"
	metadataSeverity    = "severity"
	metadataEffectiveOn = "effective_on"
	metadataSolution    = "solution"
	metadataTerm        = "term"
	metadataTitle       = "title"
)

const (
	severityWarning   = "warning"
	severityFailure   = "failure"
	severityException = "exception"
	severitySkipped   = "skipped"
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
	policySources        []source.PolicySource
	outputFormat         string
	workDir              string
	dataDir              string
	policyDir            string
	policy               ConfigProvider
	include              *Criteria
	exclude              *Criteria
	fs                   afero.Fs
	namespace            []string
	source               ecc.Source
	postEvaluationFilter PostEvaluationFilter
	policyResolver       PolicyResolver // Unified policy resolver for both pre and post-evaluation filtering
}

type conftestRunner struct {
	runner.TestRunner
}

func (r conftestRunner) Run(ctx context.Context, fileList []string) (result []Outcome, err error) {
	r.Trace = tracing.FromContext(ctx).Enabled(tracing.Opa)

	conftestResult, err := r.TestRunner.Run(ctx, fileList)
	if err != nil {
		return
	}

	result = r.processConftestResults(conftestResult)

	// Validate engine data access
	if err := r.validateEngineData(ctx); err != nil {
		return nil, err
	}

	return result, nil
}

// processConftestResults converts conftest results to our Outcome format
func (r conftestRunner) processConftestResults(conftestResult []output.CheckResult) []Outcome {
	var result []Outcome

	for _, res := range conftestResult {
		r.logConftestResult(res)

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

	return result
}

// logConftestResult logs trace and debug information for a conftest result
func (r conftestRunner) logConftestResult(res output.CheckResult) {
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
}

// validateEngineData validates that we can access the policy engine data
func (r conftestRunner) validateEngineData(ctx context.Context) error {
	// we can't reference the engine from the test runner or from the results so
	// we need to recreate it, this needs to remain the same as in
	// runner.TestRunner's Run function
	capabilities, err := conftest.LoadCapabilities(r.Capabilities)
	if err != nil {
		return err
	}

	compilerOptions := conftest.CompilerOptions{
		Strict:       r.Strict,
		RegoVersion:  r.RegoVersion,
		Capabilities: capabilities,
	}

	engine, err := conftest.LoadWithData(r.Policy, r.Data, compilerOptions)
	if err != nil {
		return err
	}

	store := engine.Store()
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return err
	}

	ids := []string{} // everything
	d, err := store.Read(ctx, txn, ids)
	if err != nil {
		return err
	}

	if _, ok := d.(map[string]any); !ok {
		return fmt.Errorf("could not retrieve data from the policy engine: Data is: %v", d)
	}

	return nil
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source) (Evaluator, error) {
	return BuildWithNamespace(ctx, policySources, p, source, []string{})
}

// NewConftestEvaluatorWithPostEvaluationFilter returns initialized conftestEvaluator with a custom post-evaluation filter
func NewConftestEvaluatorWithPostEvaluationFilter(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source, postEvaluationFilter PostEvaluationFilter) (Evaluator, error) {
	return BuildWithPostEvaluationFilter(ctx, policySources, p, source, postEvaluationFilter)
}

// NewConftestEvaluatorWithFilterType returns initialized conftestEvaluator with a specific filter type
func NewConftestEvaluatorWithFilterType(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source, filterType string) (Evaluator, error) {
	return BuildWithFilterType(ctx, policySources, p, source, filterType)
}

// NewConftestEvaluatorWithNamespaceAndFilterType returns initialized conftestEvaluator with namespace and filter type
func NewConftestEvaluatorWithNamespaceAndFilterType(
	ctx context.Context,
	policySources []source.PolicySource,
	p ConfigProvider,
	source ecc.Source,
	namespace []string,
	filterType string,
) (Evaluator, error) {
	if trace.IsEnabled() {
		r := trace.StartRegion(ctx, "ec:conftest-create-evaluator")
		defer r.End()
	}

	return NewBuilder(ctx).
		WithPolicySources(policySources).
		WithPolicy(p).
		WithSource(source).
		WithNamespace(namespace).
		WithFilterType(filterType).
		Build()
}

// set the policy namespace
func NewConftestEvaluatorWithNamespace(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source, namespace []string) (Evaluator, error) {
	// Use default filter type (include-exclude) for backward compatibility
	return NewConftestEvaluatorWithNamespaceAndFilterType(ctx, policySources, p, source, namespace, "include-exclude")
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
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:conftest-evaluate")
		defer region.End()
	}

	// Step 1: Collect rules from all policy sources
	ruleCollector := NewPolicyRuleCollector(c.fs)
	collectResult := ruleCollector.CollectRulesFromSources(ctx, c.policySources, c.workDir)
	if collectResult.Error != nil {
		return nil, collectResult.Error
	}

	// Step 2: Resolve namespaces
	namespaceManager := NewNamespaceManager(c.policyResolver, c.namespace)
	namespaceResolution := namespaceManager.ResolveNamespaces(ctx, collectResult.AllRules, target.Target)

	// Step 3: Create and run the test runner
	runner, err := c.createTestRunner(ctx, namespaceResolution)
	if err != nil {
		return nil, err
	}

	// Step 4: Execute the evaluation
	runResults, err := runner.Run(ctx, target.Inputs)
	if err != nil {
		return nil, err
	}

	// Step 5: Process results
	effectiveTime := c.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	missingIncludes := c.initializeMissingIncludes()
	resultProcessor := NewResultProcessor(c.policyResolver)

	var results []Outcome
	totalRules := 0

	for _, result := range runResults {
		processedResult, updatedMissingIncludes, err := resultProcessor.ProcessResult(
			ctx, result, collectResult.AnnotatedRules, target.Target, missingIncludes, effectiveTime)
		if err != nil {
			return nil, err
		}

		missingIncludes = updatedMissingIncludes
		totalRules += len(processedResult.Warnings) + len(processedResult.Failures) + len(processedResult.Successes)
		results = append(results, processedResult)
	}

	// Step 6: Handle missing includes and final processing
	results = c.handleMissingIncludes(results, missingIncludes)
	trim(&results)

	// Step 7: Validate that rules were actually processed
	if totalRules == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, nil
}

// createTestRunner creates and configures the test runner for evaluation.
func (c conftestEvaluator) createTestRunner(ctx context.Context, namespaceResolution NamespaceResolution) (testRunner, error) {
	r, ok := ctx.Value(runnerKey).(testRunner)
	if r != nil && ok {
		return r, nil
	}

	// Prepare the list of data dirs
	dataDirs, err := c.prepareDataDirs(ctx)
	if err != nil {
		return nil, err
	}

	log.Debugf("Data dirs: %v", dataDirs)

	return &conftestRunner{
		runner.TestRunner{
			Data:          dataDirs,
			Policy:        []string{c.policyDir},
			Namespace:     namespaceResolution.NamespacesToUse,
			AllNamespaces: namespaceResolution.AllNamespaces,
			NoFail:        true,
			Output:        c.outputFormat,
			Capabilities:  c.CapabilitiesPath(),
			RegoVersion:   "v1",
		},
	}, nil
}

// initializeMissingIncludes initializes the missing includes tracking map.
func (c conftestEvaluator) initializeMissingIncludes() map[string]bool {
	missingIncludes := map[string]bool{}
	for _, defaultItem := range c.include.defaultItems {
		missingIncludes[defaultItem] = true
	}
	for _, digestItems := range c.include.digestItems {
		for _, digestItem := range digestItems {
			missingIncludes[digestItem] = true
		}
	}
	return missingIncludes
}

// handleMissingIncludes adds warnings for missing include criteria.
func (c conftestEvaluator) handleMissingIncludes(results []Outcome, missingIncludes map[string]bool) []Outcome {
	for missingInclude, isMissing := range missingIncludes {
		if isMissing {
			results = append(results, Outcome{
				Warnings: []Result{{
					Message: fmt.Sprintf("Include criterion '%s' doesn't match any policy rule", missingInclude),
				}},
			})
		}
	}
	return results
}

// prepareDataDirs inspects the top level data dir and returns a list of the directories
// that appear to have data files in them. That list will be passed to the conftest runner.
func (c conftestEvaluator) prepareDataDirs(_ context.Context) ([]string, error) {
	// The reason we do this is to avoid having the names of the subdirs under c.dataDir
	// converted to keys in the data structure. We want the top level keys in the data files
	// to be at the top level of the data structure visible to the rego rules.

	dirsWithDataFiles := make(map[string]bool)
	err := afero.Walk(c.fs, c.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the root data directory itself
		if path == c.dataDir {
			return nil
		}

		// Only process files, not directories
		if !info.IsDir() {
			ext := filepath.Ext(info.Name())
			// Check if this is a data file (.json, .yaml, .yml)
			// Todo: Should probably recognize other supported types of data
			if ext == ".json" || ext == ".yaml" || ext == ".yml" {
				// Mark the directory containing this file as having data
				dir := filepath.Dir(path)
				dirsWithDataFiles[dir] = true
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Convert the map keys to a slice
	dataDirs := []string{}
	for dir := range dirsWithDataFiles {
		dataDirs = append(dataDirs, dir)
	}

	return dataDirs, nil
}

func toRules(results []output.Result) []Result {
	var eResults []Result
	for _, r := range results {
		// Newer conftest adds this key to the metadata. A typical value might
		// be "data.main.deny". Currently we don't use it so let's remove it
		// rather than change a bunch of snapshot files and test assertions.
		delete(r.Metadata, metadataQuery)

		eResults = append(eResults, Result{
			Message:  r.Message,
			Metadata: r.Metadata,
			Outputs:  r.Outputs,
		})
	}

	return eResults
}

func addRuleMetadata(ctx context.Context, result *Result, rules policyRules) {
	code, ok := (*result).Metadata[metadataCode].(string)
	if ok {
		addMetadataToResults(ctx, result, rules[code])
	}
	// Results without codes are handled by the filtering logic using wildcard matchers
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

	normalizeCollections(r.Metadata)
	addRuleFields(r.Metadata, rule)
	handleEffectiveOnDate(ctx, r.Metadata)
}

// normalizeCollections normalizes the collections metadata to []string format
func normalizeCollections(metadata map[string]any) {
	if v, ok := metadata[metadataCollections]; ok {
		switch vals := v.(type) {
		case []any:
			col := make([]string, 0, len(vals))
			for _, c := range vals {
				col = append(col, fmt.Sprint(c))
			}
			metadata[metadataCollections] = col
		case []string:
			// all good, mainly left for documentation of the normalization
		default:
			// remove unsupported collections attribute
			delete(metadata, metadataCollections)
		}
	}
}

// addRuleFields adds rule metadata fields to the result metadata
func addRuleFields(metadata map[string]any, rule rule.Info) {
	if rule.Title != "" {
		metadata[metadataTitle] = rule.Title
	}
	if rule.EffectiveOn != "" {
		metadata[metadataEffectiveOn] = rule.EffectiveOn
	}
	if rule.Severity != "" {
		metadata[metadataSeverity] = rule.Severity
	}
	if rule.Description != "" {
		metadata[metadataDescription] = rule.Description
	}
	if rule.Solution != "" {
		metadata[metadataSolution] = rule.Solution
	}
	if len(rule.Collections) > 0 {
		metadata[metadataCollections] = rule.Collections
	}
	if len(rule.DependsOn) > 0 {
		metadata[metadataDependsOn] = rule.DependsOn
	}
}

// handleEffectiveOnDate handles the effective_on date logic
func handleEffectiveOnDate(ctx context.Context, metadata map[string]any) {
	effectiveTime, ok := ctx.Value(effectiveTimeKey).(time.Time)
	if !ok {
		log.Warnf("Could not get effectiveTime from context")
		return
	}

	effectiveOnString, ok := metadata[metadataEffectiveOn].(string)
	if !ok {
		return
	}

	effectiveOnTime, err := time.Parse(effectiveOnFormat, effectiveOnString)
	if err != nil {
		log.Warnf("Invalid %q value %q", metadataEffectiveOn, effectiveOnString)
		return
	}

	// If the rule has been effective for a long time, we'll consider
	// the effective_on date not relevant and not bother including it
	if effectiveOnTime.Before(effectiveTime.Add(effectiveOnTimeout)) {
		delete(metadata, metadataEffectiveOn)
	}
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(ctx context.Context, dataDir string, p ConfigProvider) error {
	if p == nil {
		return nil
	}

	fs := utils.FS(ctx)

	// Place it in its own subdirectory instead of at the top level
	configDataDir := filepath.Join(dataDir, "config")
	exists, err := afero.DirExists(fs, configDataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Config data dir '%s' does not exist, will create.", dataDir)
		if err := fs.MkdirAll(configDataDir, 0755); err != nil {
			return err
		}
	}
	configFilePath := filepath.Join(configDataDir, "config.json")

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

	// Check to see if the config/config.json file exists
	exists, err = afero.Exists(fs, configFilePath)
	if err != nil {
		return err
	}
	// if so, remove it
	if exists {
		if err := fs.Remove(configFilePath); err != nil {
			return err
		}
	}
	// write our jsonData content to the config/config.json file in the data dir
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
		if err := fs.MkdirAll(dataDir, 0755); err != nil {
			return err
		}
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

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result Result) []string {
	var collections []string
	if maybeCollections, exists := result.Metadata[metadataCollections]; exists {
		if ruleCollections, ok := maybeCollections.([]string); ok {
			for _, c := range ruleCollections {
				collections = append(collections, "@"+c)
			}
		} else {
			// Log the error instead of panicking
			log.Errorf("Unsupported collections set in Metadata, expecting []string got: %v", maybeCollections)
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
	// hosts can be reached. Unfortunately, the required JSON marshaling process
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

// extractCodeFromRuleBody extracts the code value from a rule's body expressions.
// It looks for assignments like `result := { "code": "...", ... }` in the rule body.
func extractCodeFromRuleBody(ruleRef *ast.Rule) string {
	if ruleRef.Body == nil {
		return ""
	}

	for _, expr := range ruleRef.Body {
		if !expr.IsAssignment() {
			continue
		}

		if len(expr.Operands()) < 2 {
			continue
		}

		term, ok := expr.Operands()[1].Value.(ast.Object)
		if !ok {
			continue
		}

		var code string
		if err := term.Iter(func(key, value *ast.Term) error {
			if keyStr, ok := key.Value.(ast.String); ok && keyStr == "code" {
				if valueStr, ok := value.Value.(ast.String); ok {
					code = string(valueStr)
				}
			}
			return nil
		}); err != nil {
			log.Warnf("Error iterating over term: %v", err)
		}

		if code != "" {
			return code
		}
	}

	return ""
}
