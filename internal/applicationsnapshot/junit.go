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

package applicationsnapshot

import (
	"fmt"
	"sort"
	"strings"

	"cuelang.org/go/pkg/time"
	"github.com/jstemmer/go-junit-report/v2/v2/junit"
	"golang.org/x/exp/maps"

	"github.com/conforma/cli/internal/evaluator"
)

// mapResults maps an slice of Conftest results to a slice of arbitrary types
// given a mapper function
func mapResults(suite *junit.Testsuite, results []evaluator.Result, m func(evaluator.Result) junit.Testcase) {
	for _, r := range results {
		suite.AddTestcase(m(r))
	}
}

func asTestCase(r evaluator.Result) junit.Testcase {
	meta := maps.Clone(r.Metadata)
	delete(meta, "code")

	metaDesc := make([]string, 0, 3)
	for k, v := range meta {
		metaDesc = append(metaDesc, fmt.Sprintf("%s=%v", k, v))
	}

	desc := ""
	if len(metaDesc) > 0 {
		sort.Strings(metaDesc)
		desc = " [" + strings.Join(metaDesc, ", ") + "]"
	}

	name := fmt.Sprintf("%s%s", r.Message, desc)

	if code, ok := r.Metadata["code"].(string); ok {
		name = fmt.Sprintf("%s: %s", code, name)
	}

	return junit.Testcase{
		Name:      name,
		Classname: name, // some reporting tools might require Classname as well
	}
}

// toJUnit returns a version of the report in JUnit XML format
func (r *Report) toJUnit() junit.Testsuites {
	report := junit.Testsuites{}

	for _, component := range r.Components {
		properties := []junit.Property{
			{
				Name:  "image",
				Value: component.ContainerImage,
			}, {
				Name:  "key",
				Value: r.Key,
			}, {
				Name:  "success",
				Value: fmt.Sprint(component.Success),
			},
		}

		for _, s := range component.Signatures {
			properties = append(properties, junit.Property{
				Name:  "keyId",
				Value: s.KeyID,
			}, junit.Property{
				Name:  "signature",
				Value: s.Signature,
			})

			metaProps := make([]junit.Property, 0, len(s.Metadata))
			for k, v := range s.Metadata {
				metaProps = append(metaProps, junit.Property{
					Name:  "metadata." + k,
					Value: v,
				})
			}

			sort.SliceStable(metaProps, func(i, j int) bool {
				return strings.Compare(metaProps[i].Name, metaProps[j].Name) < 0
			})

			properties = append(properties, metaProps...)
		}

		suite := junit.Testsuite{
			Timestamp:  r.created.Format(time.RFC3339),
			Name:       fmt.Sprintf("%s (%s)", component.Name, component.ContainerImage),
			Properties: &properties,
		}

		mapResults(&suite, component.Successes, asTestCase)

		mapResults(&suite, component.Violations, func(r evaluator.Result) junit.Testcase {
			c := asTestCase(r)
			c.Failure = &junit.Result{
				Message: r.Message,
				Data:    r.Message,
			}

			return c
		})

		mapResults(&suite, component.Warnings, func(r evaluator.Result) junit.Testcase {
			c := asTestCase(r)
			c.Skipped = &junit.Result{
				Message: r.Message,
				Data:    r.Message,
			}

			return c
		})

		report.AddSuite(suite)
	}

	return report
}
