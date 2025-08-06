// Copyright 2024 Red Hat, Inc.
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

package main

import (
	"encoding/json"
	"testing"

	v1alpha1 "github.com/conforma/cli/api/v1alpha1"
	"github.com/santhosh-tekuri/jsonschema/v5"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestJsonAdditionalProperties(t *testing.T) {
	schema, err := jsonschema.CompileString("schema.json", v1alpha1.Schema)
	if err != nil {
		t.Errorf("unable to compile the schema for v1alpha1: %v", err)
	}

	ruleData := []byte(`{"any": "value"}`)

	policy := v1alpha1.EnterpriseContractPolicySpec{
		Sources: []v1alpha1.Source{
			{
				RuleData: &v1.JSON{
					Raw: ruleData,
				},
			},
		},
	}

	j, err := json.Marshal(policy)
	if err != nil {
		t.Errorf("unable to marshal policy to JSON: %v", err)
	}

	val := map[string]any{}
	if err := json.Unmarshal(j, &val); err != nil {
		t.Errorf("unable to unmarshal JSON: %v", err)
	}

	if err := schema.Validate(val); err != nil {
		t.Errorf("schema validation should pass, but it failed with: %v", err)
	}
}
