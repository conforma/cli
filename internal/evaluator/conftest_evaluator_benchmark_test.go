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

// This file contains benchmark tests for the Conftest Evaluator to measure
// performance characteristics. It includes benchmarks for:
// - Basic evaluation performance (BenchmarkConftestEvaluatorEvaluate)
// - Large input evaluation performance (BenchmarkConftestEvaluatorWithLargeInput)
// These benchmarks help identify performance bottlenecks and regressions
// in the evaluator's performance.

//go:build unit

package evaluator

import (
	"context"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

// setupBenchmarkEvaluator creates a common evaluator setup for benchmarks
func setupBenchmarkEvaluator(ctx context.Context) (Evaluator, error) {
	// Create policy source
	policySource := &source.PolicyUrl{
		Url:  "file://testdata/policies",
		Kind: source.PolicyKind,
	}

	// Create config provider
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://testdata/policies"},
			},
		},
	})

	// Create evaluator
	return NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{})
}

// runBenchmarkTest runs a benchmark test with the given target
func runBenchmarkTest(b *testing.B, target EvaluationTarget) {
	ctx := context.Background()

	evaluator, err := setupBenchmarkEvaluator(ctx)
	require.NoError(b, err)
	defer evaluator.Destroy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.Evaluate(ctx, target)
		require.NoError(b, err)
	}
}

func BenchmarkConftestEvaluatorEvaluate(b *testing.B) {
	target := EvaluationTarget{
		Inputs: []string{"testdata/input.json"},
		Target: "benchmark",
	}
	runBenchmarkTest(b, target)
}

func BenchmarkConftestEvaluatorWithLargeInput(b *testing.B) {
	target := EvaluationTarget{
		Inputs: []string{"testdata/large-input.json"},
		Target: "benchmark-large",
	}
	runBenchmarkTest(b, target)
}
