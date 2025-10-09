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

package vsa

import (
	"encoding/json"
	"fmt"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

// ParsePolicySpec parses a policy configuration string to extract the EnterpriseContractPolicySpec
func ParsePolicySpec(policyConfig string) (ecapi.EnterpriseContractPolicySpec, error) {
	content := []byte(policyConfig)

	// Convert YAML to JSON first to handle ruleData field mapping correctly
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(content, &yamlData); err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert interface{} types to proper types for JSON marshaling
	jsonData := ConvertYAMLToJSON(yamlData)

	// Convert to JSON bytes
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	// Now parse as JSON which should handle ruleData field mapping correctly
	var ecp ecapi.EnterpriseContractPolicy
	if err := json.Unmarshal(jsonBytes, &ecp); err == nil && ecp.APIVersion != "" {
		// Check if this is actually a valid CRD (has required fields)
		if ecp.APIVersion == "" || ecp.Kind == "" {
			// This is not a valid CRD, try parsing as EnterpriseContractPolicySpec
			var spec ecapi.EnterpriseContractPolicySpec
			if err := json.Unmarshal(jsonBytes, &spec); err != nil {
				return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
			}
			return spec, nil
		}
		return ecp.Spec, nil
	}

	// If parsing as EnterpriseContractPolicy fails, try as EnterpriseContractPolicySpec
	var spec ecapi.EnterpriseContractPolicySpec
	if err := json.Unmarshal(jsonBytes, &spec); err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
	}
	return spec, nil
}
