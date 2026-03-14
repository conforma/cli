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

// Functions for inspecting rego code and annotations
package opa

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/ast/json"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

func inspectSingle(path, module string) ([]*ast.AnnotationsRef, error) {
	// Set global JSON options to include location data for annotations
	json.SetOptions(json.Options{
		MarshalOptions: json.MarshalOptions{
			IncludeLocation: json.NodeToggle{
				AnnotationsRef: true,
			},
		},
	})

	mod, err := ast.ParseModuleWithOpts(path, module, ast.ParserOptions{
		ProcessAnnotation: true,
	})
	if err != nil {
		return nil, err
	}

	as, errs := ast.BuildAnnotationSet([]*ast.Module{mod})
	if len(errs) > 0 {
		return nil, errors.New(errs.Error())
	}

	results := make([]*ast.AnnotationsRef, 0, len(mod.Rules))
	for _, rule := range mod.Rules {
		results = append(results, as.Chain(rule)...)
	}

	return results, nil
}

func inspectMultiple(paths, modules []string) ([]*ast.AnnotationsRef, error) {
	numPaths := len(paths)
	numModules := len(modules)
	if numPaths != numModules {
		return nil, fmt.Errorf("mismatched number of paths and modules: %d != %d", numPaths, numModules)
	}

	results := make([]*ast.AnnotationsRef, 0, numPaths)
	for i := 0; i < numPaths; i++ {
		r, err := inspectSingle(paths[i], modules[i])
		if err != nil {
			return nil, err
		}

		results = append(results, r...)
	}

	return results, nil
}

// Borrowed from conftest
func isWarning(ruleName string) bool {
	return regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$").MatchString(ruleName)
}

// Borrowed from conftest
func isFailure(ruleName string) bool {
	return regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$").MatchString(ruleName)
}

func isWarnOrDeny(rule *ast.AnnotationsRef) bool {
	r := rule.GetRule()
	if r == nil {
		return false
	}
	ruleName := r.Head.Name.String()
	return isWarning(ruleName) || isFailure(ruleName)
}

func hasAnnotations(rule *ast.AnnotationsRef) bool {
	return rule.Annotations != nil
}

// Interesting rules are warns, denies, and anything with an annotation,
// which includes some package scoped annotations not assocated with a rule
func interestingRulesOnly(results []*ast.AnnotationsRef) []*ast.AnnotationsRef {
	filteredResults := make([]*ast.AnnotationsRef, 0, len(results))
	for _, rule := range results {
		if isWarnOrDeny(rule) || hasAnnotations(rule) {
			filteredResults = append(filteredResults, rule)
		}
	}
	return filteredResults
}

// destDir is usually something like /tmp/ec-workdir-1234/policy/f33dbeef so let's trim it
func shortPath(fullPath string, destDir string) string {
	return strings.TrimPrefix(strings.TrimPrefix(fullPath, destDir), "/")
}

func checkRules(rules []*ast.AnnotationsRef) error {
	for _, rule := range rules {
		r := rule.GetRule()
		if r == nil {
			// not a rule
			continue
		}
		head := r.Head
		term := head.Value
		var value ast.Value
		if term != nil {
			// cases when rule is assigned, e.g. deny = msg {...}
			value = term.Value
		} else {
			// cases when rule is keyed, e.g. deny[msg] {...}
			key := head.Key
			value = key.Value
		}

		switch value.(type) {
		case ast.String:
			continue
		case *ast.String:
			continue
		case ast.Object:
			continue
		case ast.Var:
			continue
		case ast.Call:
			continue
		}

		return fmt.Errorf("the rule %q returns an unsupported value, at %s", r.String(), r.Location)
	}

	return nil
}

// Finds all the rego files, inspects each one and returns a list the inspect data
func InspectDir(afs afero.Fs, dir string) ([]*ast.AnnotationsRef, error) {
	regoPaths := []string{}
	regoContents := []string{}

	// Find all the rego files
	// IMPORTANT: Resist the temptation to use afero.WalkDir here. If dir is a symlink, afero.Walk
	// will not follow it. This is the case if dir was created by go-getter from a local file path.
	// See afero issue https://github.com/spf13/afero/issues/284.
	err := fs.WalkDir(wrapperFs{afs: afs}, dir, func(path string, d fs.DirEntry, readErr error) error {
		if readErr != nil {
			return readErr
		}

		if d.IsDir() {
			return nil
		}

		pathLower := strings.ToLower(path)

		if filepath.Ext(pathLower) != ".rego" {
			return nil
		}

		// Prune out the tests early on
		if strings.HasSuffix(filepath.Base(pathLower), "_test.rego") {
			return nil
		}

		contents, err := afero.ReadFile(afs, path)
		if err != nil {
			return nil
		}

		regoPaths = append(regoPaths, shortPath(path, dir))
		regoContents = append(regoContents, string(contents))
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Ensure that we have actual rules, and a directory without rego files.
	if len(regoPaths) == 0 {
		log.Debug("No rego files found after cloning policy url.")
		return nil, errors.New("no rego files found in policy subdirectory")
	}

	// Inspect all rego files found
	allAnnotations, err := inspectMultiple(regoPaths, regoContents)
	if err != nil {
		return nil, err
	}

	// Return only interesting rules
	result := interestingRulesOnly(allAnnotations)

	// check for conformance
	if err := checkRules(result); err != nil {
		return nil, err
	}

	return result, nil
}

// wrapperFs turns afero.Fs into fs.FS so it can be used in certain functions
// provided by the fs package, e.g fs.WalkDir.
type wrapperFs struct {
	afs afero.Fs
}

// Open exists to make the aferoFsWrapper conform to the fs.FS interface. It is necessary
// to do this in order to change the first return type from afero.File to fs.File. Yes,
// even though afero.File conforms to the fs.File interface, go is not smart enough to
// detect this indirection.
func (w wrapperFs) Open(name string) (fs.File, error) {
	return w.afs.Open(name)
}
