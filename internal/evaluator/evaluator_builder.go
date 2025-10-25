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
	"path/filepath"

	ecc "github.com/conforma/crds/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// Builder provides a fluent interface for building ConftestEvaluator instances.
type Builder struct {
	ctx                  context.Context
	policySources        []source.PolicySource
	policy               ConfigProvider
	source               ecc.Source
	namespace            []string
	filterType           string
	postEvaluationFilter PostEvaluationFilter
}

// NewEvaluatorBuilder creates a new EvaluatorBuilder instance.
func NewBuilder(ctx context.Context) *Builder {
	return &Builder{
		ctx:        ctx,
		filterType: "include-exclude", // default filter type
	}
}

// WithPolicySources sets the policy sources for the evaluator.
func (eb *Builder) WithPolicySources(sources []source.PolicySource) *Builder {
	eb.policySources = sources
	return eb
}

// WithPolicy sets the policy configuration provider.
func (eb *Builder) WithPolicy(policy ConfigProvider) *Builder {
	eb.policy = policy
	return eb
}

// WithSource sets the source configuration.
func (eb *Builder) WithSource(source ecc.Source) *Builder {
	eb.source = source
	return eb
}

// WithNamespace sets the namespace for the evaluator.
func (eb *Builder) WithNamespace(namespace []string) *Builder {
	eb.namespace = namespace
	return eb
}

// WithFilterType sets the filter type for the evaluator.
func (eb *Builder) WithFilterType(filterType string) *Builder {
	eb.filterType = filterType
	return eb
}

// WithPostEvaluationFilter sets the post-evaluation filter.
func (eb *Builder) WithPostEvaluationFilter(filter PostEvaluationFilter) *Builder {
	eb.postEvaluationFilter = filter
	return eb
}

// Build creates a new ConftestEvaluator instance with the configured options.
func (eb *Builder) Build() (Evaluator, error) {
	fs := utils.FS(eb.ctx)

	evaluator := &conftestEvaluator{
		policySources: eb.policySources,
		outputFormat:  "json",
		policy:        eb.policy,
		fs:            fs,
		namespace:     eb.namespace,
		source:        eb.source,
	}

	// Initialize the policy resolver based on filter type
	switch eb.filterType {
	case "ec-policy":
		evaluator.policyResolver = NewECPolicyResolver(eb.source, eb.policy)
	case "include-exclude":
		fallthrough
	default:
		evaluator.policyResolver = NewIncludeExcludePolicyResolver(eb.source, eb.policy)
	}

	// Extract include/exclude criteria from the policy resolver to maintain backward compatibility
	// for the legacy isResultIncluded method
	evaluator.include = evaluator.policyResolver.Includes()
	evaluator.exclude = evaluator.policyResolver.Excludes()

	// Set up working directory
	if err := eb.setupWorkingDirectory(evaluator); err != nil {
		return nil, err
	}

	// Set post-evaluation filter if provided
	if eb.postEvaluationFilter != nil {
		evaluator.postEvaluationFilter = eb.postEvaluationFilter
	}

	log.Debug("Conftest test runner created")
	return evaluator, nil
}

// setupWorkingDirectory creates and configures the working directory for the evaluator.
func (eb *Builder) setupWorkingDirectory(evaluator *conftestEvaluator) error {
	dir, err := utils.CreateWorkDir(evaluator.fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return err
	}

	evaluator.workDir = dir
	evaluator.policyDir = filepath.Join(evaluator.workDir, "policy")
	evaluator.dataDir = filepath.Join(evaluator.workDir, "data")

	if err := evaluator.createDataDirectory(eb.ctx); err != nil {
		return err
	}

	log.Debugf("Created work dir %s", dir)

	if err := evaluator.createCapabilitiesFile(eb.ctx); err != nil {
		return err
	}

	return nil
}

// Convenience methods for common builder patterns

// BuildWithNamespace creates an evaluator with a specific namespace.
func BuildWithNamespace(
	ctx context.Context,
	policySources []source.PolicySource,
	policy ConfigProvider,
	source ecc.Source,
	namespace []string,
) (Evaluator, error) {
	return NewBuilder(ctx).
		WithPolicySources(policySources).
		WithPolicy(policy).
		WithSource(source).
		WithNamespace(namespace).
		Build()
}

// BuildWithFilterType creates an evaluator with a specific filter type.
func BuildWithFilterType(
	ctx context.Context,
	policySources []source.PolicySource,
	policy ConfigProvider,
	source ecc.Source,
	filterType string,
) (Evaluator, error) {
	return NewBuilder(ctx).
		WithPolicySources(policySources).
		WithPolicy(policy).
		WithSource(source).
		WithFilterType(filterType).
		Build()
}

// BuildWithPostEvaluationFilter creates an evaluator with a post-evaluation filter.
func BuildWithPostEvaluationFilter(
	ctx context.Context,
	policySources []source.PolicySource,
	policy ConfigProvider,
	source ecc.Source,
	postEvaluationFilter PostEvaluationFilter,
) (Evaluator, error) {
	return NewBuilder(ctx).
		WithPolicySources(policySources).
		WithPolicy(policy).
		WithSource(source).
		WithPostEvaluationFilter(postEvaluationFilter).
		Build()
}
