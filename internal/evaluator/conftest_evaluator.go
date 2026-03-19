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
	"io/fs"
	"net/url"
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
	"github.com/open-policy-agent/opa/v1/storage"
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
	policySources  []source.PolicySource
	outputFormat   string
	workDir        string
	dataDir        string
	policyDir      string
	policy         ConfigProvider
	include        *Criteria
	exclude        *Criteria
	fs             afero.Fs
	namespace      []string
	source         ecc.Source
	policyResolver PolicyResolver // Unified policy resolver for both pre and post-evaluation filtering
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
	capabilities, err := conftest.LoadCapabilities(r.Capabilities)
	if err != nil {
		return
	}
	compilerOptions := conftest.CompilerOptions{
		Strict:       r.Strict,
		RegoVersion:  r.RegoVersion,
		Capabilities: capabilities,
	}
	engine, err = conftest.LoadWithData(r.Policy, r.Data, compilerOptions)
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

	d, err := store.Read(ctx, txn, ids)
	if err != nil {
		return
	}

	if _, ok := d.(map[string]any); !ok {
		err = fmt.Errorf("could not retrieve data from the policy engine: Data is: %v", d)
	}

	return
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespace(ctx, policySources, p, source, []string{})
}

// NewConftestEvaluatorWithFilterType returns initialized conftestEvaluator with a specific filter type
func NewConftestEvaluatorWithFilterType(ctx context.Context, policySources []source.PolicySource, p ConfigProvider, source ecc.Source, filterType string) (Evaluator, error) {
	return NewConftestEvaluatorWithNamespaceAndFilterType(ctx, policySources, p, source, []string{}, filterType)
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

	fs := utils.FS(ctx)
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
		namespace:     namespace,
		source:        source,
	}

	// Initialize the policy resolver based on filter type
	switch filterType {
	case "ec-policy":
		c.policyResolver = NewECPolicyResolver(source, p)
	case "include-exclude":
		fallthrough
	default:
		c.policyResolver = NewIncludeExcludePolicyResolver(source, p)
	}

	// Extract include/exclude criteria from the policy resolver to maintain backward compatibility
	// for the legacy isResultIncluded method
	c.include = c.policyResolver.Includes()
	c.exclude = c.policyResolver.Excludes()

	dir, err := utils.CreateWorkDir(fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir
	c.policyDir = filepath.Join(c.workDir, "policy")
	c.dataDir = filepath.Join(c.workDir, "data")

	// Write embedded rego files to policy directory
	if err := utils.WriteEmbeddedRego(ctx, fs, c.policyDir); err != nil {
		log.Warnf("Failed to write embedded rego files: %v", err)
		// Continue without embedded files - graceful degradation
	}

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

type policyRules map[string]rule.Info

// Add a new type to track non-annotated rules separately
type nonAnnotatedRules map[string]bool

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
	// Track non-annotated rules separately for filtering purposes only
	nonAnnotatedRules := nonAnnotatedRules{}
	// Track data source directories for prepareDataDirs
	dataSourceDirs := []string{}
	// Download all sources
	for _, s := range c.policySources {
		dir, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}
		// Track data source directories - these are the actual directories returned by GetPolicy
		// which may be symlinks, so we need to use them directly rather than walking
		if s.Subdir() == "data" {
			dataSourceDirs = append(dataSourceDirs, dir)
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

		// Collect ALL rules for filtering purposes - both with and without annotations
		// This ensures that rules without metadata (like fail_with_data.rego) are properly included
		for _, a := range annotations {
			if a.Annotations != nil {
				// Rules with annotations - collect full metadata
				if err := rules.collect(a); err != nil {
					return nil, err
				}
			} else {
				// Rules without annotations - track for filtering only, not for success computation
				ruleRef := a.GetRule()
				if ruleRef != nil {
					// Extract package name from the rule path
					packageName := ""
					if len(a.Path) > 1 {
						// Path format is typically ["data", "package", "rule"]
						// We want the package part (index 1)
						if len(a.Path) >= 2 {
							packageName = strings.ReplaceAll(a.Path[1].String(), `"`, "")
						}
					}

					// Try to extract code from rule body first, fallback to rule name
					code := extractCodeFromRuleBody(ruleRef)

					// If no code found in body, use rule name
					if code == "" {
						shortName := ruleRef.Head.Name.String()
						code = fmt.Sprintf("%s.%s", packageName, shortName)
					}

					// Debug: Print non-annotated rule processing
					log.Debugf("Non-annotated rule: packageName=%s, code=%s", packageName, code)

					// Track for filtering but don't add to rules map for success computation
					nonAnnotatedRules[code] = true
				}
			}
		}
	}

	// Prepare all rules for policy resolution (both annotated and non-annotated)
	// Combine annotated and non-annotated rules for filtering
	allRules := make(policyRules)
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

	var filteredNamespaces []string
	if c.policyResolver != nil {
		// IMPLEMENTATION: Option A - Unified Policy Resolution
		// Use the same PolicyResolver for both pre-evaluation and post-evaluation filtering
		// This ensures consistent logic and eliminates duplication
		policyResolution := c.policyResolver.ResolvePolicy(allRules, target.Target)

		// Extract included package names for conftest evaluation
		for pkg := range policyResolution.IncludedPackages {
			filteredNamespaces = append(filteredNamespaces, pkg)
		}

		log.Debugf("Policy resolution: %d packages included",
			len(policyResolution.IncludedPackages))
		log.Debugf("Policy resolution details: included=%v",
			policyResolution.IncludedPackages)
	} else {
		// Legacy filtering approach - use the old namespace filtering logic
		// This ensures backward compatibility with existing tests
		log.Debugf("Using legacy filtering approach")
		// For legacy tests, we don't filter namespaces at the conftest level
		// Instead, we evaluate all namespaces and filter results afterward
	}

	r, ok := ctx.Value(runnerKey).(testRunner)
	if r == nil || !ok {

		// Determine which namespaces to use
		namespacesToUse := c.namespace
		allNamespaces := false

		// If we have filtered namespaces from the filtering system, use those
		if len(filteredNamespaces) > 0 {
			namespacesToUse = filteredNamespaces

		} else if len(namespacesToUse) == 0 {
			// For new filtering with empty namespaces, also evaluate all namespaces
			// This ensures backward compatibility with tests that don't specify namespaces
			allNamespaces = true
		}

		// log the namespaces to use
		log.Debugf("Namespaces to use: %v, allNamespaces: %v", namespacesToUse, allNamespaces)

		// Prepare the list of data dirs
		dataDirs, err := c.prepareDataDirs(ctx, dataSourceDirs)
		if err != nil {
			return nil, err
		}

		r = &conftestRunner{
			runner.TestRunner{
				Data:          dataDirs,
				Policy:        []string{c.policyDir},
				Namespace:     namespacesToUse,
				AllNamespaces: allNamespaces, // Use all namespaces for legacy filtering
				NoFail:        true,
				Output:        c.outputFormat,
				Capabilities:  c.CapabilitiesPath(),
				RegoVersion:   "v1",
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
	for _, result := range runResults {
		// Use unified post-evaluation filter for consistent filtering logic

		unifiedFilter := NewUnifiedPostEvaluationFilter(c.policyResolver)

		// Collect all results for processing
		allResults := []Result{}
		allResults = append(allResults, result.Warnings...)
		allResults = append(allResults, result.Failures...)
		allResults = append(allResults, result.Exceptions...)
		allResults = append(allResults, result.Skipped...)

		// Add metadata to all results
		for j := range allResults {
			addRuleMetadata(ctx, &allResults[j], rules)
		}

		// Filter results using the unified filter
		filteredResults, updatedMissingIncludes := unifiedFilter.FilterResults(
			allResults, allRules, target.Target, target.ComponentName, missingIncludes, effectiveTime)

		// Update missing includes
		missingIncludes = updatedMissingIncludes

		// Categorize results using the unified filter
		warnings, failures, exceptions, skipped := unifiedFilter.CategorizeResults(
			filteredResults, result, effectiveTime)

		result.Warnings = warnings
		result.Failures = failures
		result.Exceptions = exceptions
		result.Skipped = skipped

		// Replace the placeholder successes slice with the actual successes.
		result.Successes = c.computeSuccesses(result, rules, target.Target, target.ComponentName, missingIncludes, unifiedFilter)

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

// prepareDataDirs inspects the data source directories and base data dir to return a list of
// directories that contain data files. That list will be passed to the conftest runner.
// dataSourceDirs contains the directories returned by GetPolicy for data sources.
// These directories may be symlinks (from cached downloads), but we walk them directly
// which ensures we find the files regardless of whether they're symlinks or not.
func (c conftestEvaluator) prepareDataDirs(ctx context.Context, dataSourceDirs []string) ([]string, error) {
	// The reason we do this is to avoid having the names of the subdirs under c.dataDir
	// converted to keys in the data structure. We want the top level keys in the data files
	// to be at the top level of the data structure visible to the rego rules.

	dirsWithDataFiles := make(map[string]bool)

	// Walk each data source directory returned by GetPolicy
	// These are the actual directories (possibly symlinks) where data was downloaded
	// Walking them directly ensures we find files even if they're symlinks
	for _, dataSourceDir := range dataSourceDirs {
		// IMPORTANT: Use fs.WalkDir instead of afero.Walk because afero.Walk does not follow symlinks.
		// When cached downloads create symlinks (as in getPolicyThroughCache), afero.Walk won't traverse
		// into the symlinked directories, causing data files to be missed.
		// See afero issue https://github.com/spf13/afero/issues/284 and internal/opa/inspect.go for reference.
		err := fs.WalkDir(opaWrapperFs{afs: c.fs}, dataSourceDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Only process files, not directories
			if !d.IsDir() {
				ext := filepath.Ext(d.Name())
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
			// Continue with other directories even if one fails
			continue
		}
	}

	// Also walk the base data directory to find config.json and any other files
	// This ensures we don't miss files that weren't from GetPolicy sources
	err := fs.WalkDir(opaWrapperFs{afs: c.fs}, c.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip the root data directory itself
		if path == c.dataDir {
			return nil
		}

		// Only process files, not directories
		if !d.IsDir() {
			ext := filepath.Ext(d.Name())
			// Check if this is a data file (.json, .yaml, .yml)
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

// computeSuccesses generates success results, these are not provided in the
// Conftest results, so we reconstruct these from the parsed rules, any rule
// that hasn't been touched by adding metadata must have succeeded
func (c conftestEvaluator) computeSuccesses(
	result Outcome,
	rules policyRules,
	imageRef string,
	componentName string,
	missingIncludes map[string]bool,
	unifiedFilter PostEvaluationFilter,
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

		// Use unified filtering approach for consistency
		if unifiedFilter != nil {
			// Use the unified filter to check if this success should be included
			filteredResults, _ := unifiedFilter.FilterResults(
				[]Result{success}, rules, imageRef, componentName, missingIncludes, time.Now())

			if len(filteredResults) == 0 {
				log.Debugf("Skipping result success: %#v", success)
				continue
			}
		} else {
			// Fallback to legacy filtering for backward compatibility
			if !c.isResultIncluded(success, imageRef, componentName, missingIncludes) {
				log.Debugf("Skipping result success: %#v", success)
				continue
			}
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
func (c conftestEvaluator) isResultIncluded(result Result, imageRef string, componentName string, missingIncludes map[string]bool) bool {
	ruleMatchers := LegacyMakeMatchers(result)
	includeScore := LegacyScoreMatches(ruleMatchers, c.include.get(imageRef, componentName), missingIncludes)
	excludeScore := LegacyScoreMatches(ruleMatchers, c.exclude.get(imageRef, componentName), map[string]bool{})
	return includeScore > excludeScore
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

// opaWrapperFs wraps afero.Fs to implement fs.FS interface for use with fs.WalkDir.
// This ensures symlinks are followed when walking directories, which is critical
// when cached downloads create symlinks via getPolicyThroughCache.
// See internal/opa/inspect.go for the original implementation.
type opaWrapperFs struct {
	afs afero.Fs
}

func (w opaWrapperFs) Open(name string) (fs.File, error) {
	return w.afs.Open(name)
}
