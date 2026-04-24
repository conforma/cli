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

package validate

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

// MergePolicyConfigs performs a deep merge of multiple policy configurations.
// The base config is merged with each overlay in order, with later overlays
// taking precedence. Arrays are concatenated and maps are deeply merged.
func MergePolicyConfigs(ctx context.Context, base string, overlays []string) (string, error) {
	if len(overlays) == 0 {
		return base, nil
	}

	log.Debugf("Merging base policy with %d overlay(s)", len(overlays))

	// Parse base config
	var baseData map[string]interface{}
	if err := yaml.Unmarshal([]byte(base), &baseData); err != nil {
		return "", fmt.Errorf("failed to parse base policy config: %w", err)
	}

	// Merge each overlay in order
	for i, overlay := range overlays {
		var overlayData map[string]interface{}
		if err := yaml.Unmarshal([]byte(overlay), &overlayData); err != nil {
			return "", fmt.Errorf("failed to parse policy overlay %d: %w", i, err)
		}

		log.Debugf("Applying policy overlay %d", i)
		baseData = deepMerge(baseData, overlayData)
	}

	// Marshal back to YAML
	result, err := yaml.Marshal(baseData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal merged policy config: %w", err)
	}

	return string(result), nil
}

// deepMerge performs a deep merge of two maps.
// - For maps: recursively merge keys, with overlay taking precedence
// - For arrays: concatenate base and overlay
// - For other types: overlay value replaces base value
func deepMerge(base, overlay map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy all base values
	for k, v := range base {
		result[k] = v
	}

	// Merge overlay values
	for k, overlayVal := range overlay {
		baseVal, exists := result[k]
		if !exists {
			// Key doesn't exist in base, just add it
			result[k] = overlayVal
			continue
		}

		// Both base and overlay have this key - need to merge
		baseMap, baseIsMap := baseVal.(map[string]interface{})
		overlayMap, overlayIsMap := overlayVal.(map[string]interface{})

		if baseIsMap && overlayIsMap {
			// Both are maps - recursively merge
			result[k] = deepMerge(baseMap, overlayMap)
		} else if baseSlice, baseIsSlice := baseVal.([]interface{}); baseIsSlice {
			if overlaySlice, overlayIsSlice := overlayVal.([]interface{}); overlayIsSlice {
				// Both are slices - concatenate
				result[k] = append(baseSlice, overlaySlice...)
			} else {
				// Type mismatch - overlay wins
				result[k] = overlayVal
			}
		} else {
			// Scalar value or type mismatch - overlay wins
			result[k] = overlayVal
		}
	}

	return result
}
