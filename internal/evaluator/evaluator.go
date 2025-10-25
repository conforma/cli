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

	"github.com/conforma/cli/internal/opa/rule"
)

type EvaluationTarget struct {
	Inputs []string
	Target string
}

type Evaluator interface {
	Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, error)

	// Destroy performs any cleanup needed
	Destroy()

	// CapabilitiesPath returns the path to the file where capabilities are defined
	CapabilitiesPath() string
}

type Data map[string]any

type Outcome struct {
	FileName   string   `json:"filename"`
	Namespace  string   `json:"namespace"`
	Successes  []Result `json:"successes,omitempty"`
	Skipped    []Result `json:"skipped,omitempty"`
	Warnings   []Result `json:"warnings,omitempty"`
	Failures   []Result `json:"failures,omitempty"`
	Exceptions []Result `json:"exceptions,omitempty"`
}

type Result struct {
	Message  string                 `json:"msg"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Outputs  []string               `json:"outputs,omitempty"`
}

// policyRules is a map of rule codes to rule information
type policyRules map[string]rule.Info

// nonAnnotatedRules is a map of rule codes to boolean flags for non-annotated rules
type nonAnnotatedRules map[string]bool
