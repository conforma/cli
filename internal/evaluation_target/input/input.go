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

package input

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

var newConftestEvaluator = evaluator.NewConftestEvaluator
var newOPAEvaluator = evaluator.NewOPAEvaluator

// Input represents the structure needed to evaluate a generic file input
type Input struct {
	Paths      []string
	Evaluators []evaluator.Evaluator
}

// NewInput returns a Input struct with FPath and evaluator ready to use
func NewInput(ctx context.Context, paths []string, p policy.Policy) (*Input, error) {
	i := &Input{
		Paths: paths,
	}

	for _, sourceGroup := range p.Spec().Sources {
		// Todo: Make each fetch run concurrently
		policySources := source.PolicySourcesFrom(sourceGroup)

		for _, policySource := range policySources {
			log.Debugf("policySource: %#v", policySource)
		}

		var c evaluator.Evaluator
		var err error
		if utils.IsOpaEnabled() {
			c, err = newOPAEvaluator(ctx, policySources, p, sourceGroup, nil)
		} else {
			c, err = newConftestEvaluator(ctx, policySources, p, sourceGroup)
		}
		if err != nil {
			log.Debug("Failed to initialize the evaluator!")
			return nil, err
		}

		log.Debug("Evaluator initialized")
		i.Evaluators = append(i.Evaluators, c)

	}
	return i, nil
}
