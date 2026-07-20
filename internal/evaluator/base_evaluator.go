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
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/open-policy-agent/opa/v1/ast"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/opa"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

type basePolicyEvaluator struct {
	policySources  []source.PolicySource
	workDir        string
	dataDir        string
	policyDir      string
	policy         ConfigProvider
	include        *Criteria
	exclude        *Criteria
	fs             afero.Fs
	namespace      []string
	source         ecc.Source
	policyResolver PolicyResolver

	rules          policyRules
	nonAnnotated   nonAnnotatedRules
	allRules       policyRules
	dataSourceDirs []string
}

func (b *basePolicyEvaluator) initPolicyResolver(src ecc.Source, p ConfigProvider) {
	b.policyResolver = NewIncludeExcludePolicyResolver(src, p)
	b.include = b.policyResolver.Includes()
	b.exclude = b.policyResolver.Excludes()
}

func (b *basePolicyEvaluator) initWorkDir(ctx context.Context) error {
	dir, err := utils.CreateWorkDir(b.fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return err
	}
	b.workDir = dir
	b.policyDir = filepath.Join(b.workDir, "policy")
	b.dataDir = filepath.Join(b.workDir, "data")

	if err := b.createDataDirectory(ctx); err != nil {
		return err
	}
	log.Debugf("Created work dir %s", dir)

	if err := b.createCapabilitiesFile(ctx); err != nil {
		return err
	}
	return nil
}

func (b *basePolicyEvaluator) Destroy() {
	if b.workDir != "" && os.Getenv("EC_DEBUG") == "" {
		_ = b.fs.RemoveAll(b.workDir)
	}
}

func (b *basePolicyEvaluator) CapabilitiesPath() string {
	return path.Join(b.workDir, "capabilities.json")
}

func (b *basePolicyEvaluator) createDataDirectory(ctx context.Context) error {
	afs := utils.FS(ctx)
	exists, err := afero.DirExists(afs, b.dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", b.dataDir)
		if err := afs.MkdirAll(b.dataDir, 0755); err != nil {
			return err
		}
	}
	return createConfigJSON(ctx, b.dataDir, b.policy)
}

func (b *basePolicyEvaluator) createCapabilitiesFile(ctx context.Context) error {
	afs := utils.FS(ctx)
	f, err := afs.Create(b.CapabilitiesPath())
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

func (b *basePolicyEvaluator) downloadAndInspectPolicies(ctx context.Context) error {
	b.rules = policyRules{}
	b.nonAnnotated = nonAnnotatedRules{}
	b.dataSourceDirs = []string{}

	for _, s := range b.policySources {
		dir, err := s.GetPolicy(ctx, b.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			return err
		}
		if s.Subdir() == "data" {
			b.dataSourceDirs = append(b.dataSourceDirs, dir)
		}

		annotations := []*ast.AnnotationsRef{}
		afs := utils.FS(ctx)
		if s.Subdir() == "policy" {
			annotations, err = opa.InspectDir(afs, dir)
			if err != nil {
				errMsg := err
				if err.Error() == "no rego files found in policy subdirectory" {
					policyURL, err := url.Parse(s.PolicyUrl())
					if err != nil {
						return errMsg
					}
					pos := strings.LastIndex(policyURL.Path, ".")
					if pos == -1 {
						if (policyURL.Host == "github.com" || policyURL.Host == "gitlab.com") && (policyURL.Scheme == "https" || policyURL.Scheme == "http") {
							log.Debug("Git Hub or GitLab, http transport, and no file extension, this could be a problem.")
							errMsg = fmt.Errorf("%s.\nYou've specified a %s URL with an %s:// scheme.\nDid you mean: %s instead?", errMsg, policyURL.Hostname(), policyURL.Scheme, fmt.Sprint(policyURL.Host+policyURL.RequestURI()))
						}
					}
				}
				return errMsg
			}
		}

		for _, a := range annotations {
			if a.Annotations != nil {
				if err := b.rules.collect(a); err != nil {
					return err
				}
			} else {
				ruleRef := a.GetRule()
				if ruleRef != nil {
					packageName := ""
					if len(a.Path) > 1 {
						if len(a.Path) >= 2 {
							packageName = strings.ReplaceAll(a.Path[1].String(), `"`, "")
						}
					}

					code := extractCodeFromRuleBody(ruleRef)
					if code == "" {
						shortName := ruleRef.Head.Name.String()
						code = fmt.Sprintf("%s.%s", packageName, shortName)
					}

					log.Debugf("Non-annotated rule: packageName=%s, code=%s", packageName, code)
					b.nonAnnotated[code] = true
				}
			}
		}
	}

	b.allRules = make(policyRules)
	for code, r := range b.rules {
		b.allRules[code] = r
	}
	for code := range b.nonAnnotated {
		parts := strings.Split(code, ".")
		if len(parts) >= 2 {
			packageName := parts[len(parts)-2]
			shortName := parts[len(parts)-1]
			b.allRules[code] = rule.Info{
				Code:      code,
				Package:   packageName,
				ShortName: shortName,
			}
		}
	}

	return nil
}

func (b *basePolicyEvaluator) prepareDataDirs(ctx context.Context) ([]string, error) {
	dirsWithDataFiles := make(map[string]bool)

	for _, dataSourceDir := range b.dataSourceDirs {
		err := fs.WalkDir(opaWrapperFs{afs: b.fs}, dataSourceDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				ext := filepath.Ext(d.Name())
				if ext == ".json" || ext == ".yaml" || ext == ".yml" {
					dirsWithDataFiles[filepath.Dir(p)] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	err := fs.WalkDir(opaWrapperFs{afs: b.fs}, b.dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == b.dataDir {
			return nil
		}
		if !d.IsDir() {
			ext := filepath.Ext(d.Name())
			if ext == ".json" || ext == ".yaml" || ext == ".yml" {
				dirsWithDataFiles[filepath.Dir(p)] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	dataDirs := make([]string, 0, len(dirsWithDataFiles))
	for dir := range dirsWithDataFiles {
		dataDirs = append(dataDirs, dir)
	}
	return dataDirs, nil
}

func (b *basePolicyEvaluator) resolveFilteredNamespaces(target EvaluationTarget) []string {
	if b.policyResolver != nil {
		policyResolution := b.policyResolver.ResolvePolicy(b.allRules, target.Target)
		var ns []string
		for pkg := range policyResolution.IncludedPackages {
			ns = append(ns, pkg)
		}
		log.Debugf("Policy resolution: %d packages included",
			len(policyResolution.IncludedPackages))
		return ns
	}
	return nil
}

func (b *basePolicyEvaluator) postProcessResults(ctx context.Context, runResults []Outcome, target EvaluationTarget) ([]Outcome, error) {
	effectiveTime := b.policy.EffectiveTime()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTime)

	totalRules := 0

	missingIncludes := map[string]bool{}
	for _, defaultItem := range b.include.defaultItems {
		missingIncludes[defaultItem] = true
	}
	for _, digestItems := range b.include.digestItems {
		for _, digestItem := range digestItems {
			missingIncludes[digestItem] = true
		}
	}

	var results []Outcome
	for _, result := range runResults {
		unifiedFilter := NewUnifiedPostEvaluationFilter(b.policyResolver)

		allResults := []Result{}
		allResults = append(allResults, result.Warnings...)
		allResults = append(allResults, result.Failures...)
		allResults = append(allResults, result.Exceptions...)
		allResults = append(allResults, result.Skipped...)

		for j := range allResults {
			addRuleMetadata(ctx, &allResults[j], b.rules)
		}

		filteredResults, updatedMissingIncludes := unifiedFilter.FilterResults(
			allResults, b.allRules, target.Target, target.ComponentName, missingIncludes, effectiveTime)
		missingIncludes = updatedMissingIncludes

		warnings, failures, exceptions, skipped := unifiedFilter.CategorizeResults(
			filteredResults, result, effectiveTime)

		result.Warnings = warnings
		result.Failures = failures
		result.Exceptions = exceptions
		result.Skipped = skipped

		result.Successes = b.computeSuccesses(result, b.rules, target.Target, target.ComponentName, missingIncludes, unifiedFilter, effectiveTime)

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

	if totalRules == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}

	return results, nil
}

func (b *basePolicyEvaluator) computeSuccesses(
	result Outcome,
	rules policyRules,
	imageRef string,
	componentName string,
	missingIncludes map[string]bool,
	unifiedFilter PostEvaluationFilter,
	effectiveTime time.Time,
) []Result {
	seenRules := map[string]bool{}
	for _, outcomes := range [][]Result{result.Failures, result.Warnings, result.Skipped, result.Exceptions} {
		for _, r := range outcomes {
			if code, ok := r.Metadata[metadataCode].(string); ok {
				seenRules[code] = true
			}
		}
	}

	var successes []Result
	if l := len(rules); l > 0 {
		successes = make([]Result, 0, l)
	}

	for code, r := range rules {
		if seenRules[code] {
			continue
		}
		if r.Package != result.Namespace {
			continue
		}

		success := Result{
			Message: "Pass",
			Metadata: map[string]interface{}{
				metadataCode: code,
			},
		}
		if r.Title != "" {
			success.Metadata[metadataTitle] = r.Title
		}
		if r.Description != "" {
			success.Metadata[metadataDescription] = r.Description
		}
		if len(r.Collections) > 0 {
			success.Metadata[metadataCollections] = r.Collections
		}
		if len(r.DependsOn) > 0 {
			success.Metadata[metadataDependsOn] = r.DependsOn
		}

		if unifiedFilter != nil {
			filteredResults, _ := unifiedFilter.FilterResults(
				[]Result{success}, rules, imageRef, componentName, missingIncludes, effectiveTime)
			if len(filteredResults) == 0 {
				log.Debugf("Skipping result success: %#v", success)
				continue
			}
		} else {
			if !b.isResultIncluded(success, imageRef, componentName, missingIncludes) {
				log.Debugf("Skipping result success: %#v", success)
				continue
			}
		}

		if r.EffectiveOn != "" {
			success.Metadata[metadataEffectiveOn] = r.EffectiveOn
		}

		successes = append(successes, success)
	}

	return successes
}

func (b *basePolicyEvaluator) isResultIncluded(result Result, imageRef string, componentName string, missingIncludes map[string]bool) bool {
	ruleMatchers := LegacyMakeMatchers(result)
	includeScore := LegacyScoreMatches(ruleMatchers, b.include.get(imageRef, componentName), missingIncludes)
	excludeScore := LegacyScoreMatches(ruleMatchers, b.exclude.get(imageRef, componentName), map[string]bool{})
	return includeScore > excludeScore
}
