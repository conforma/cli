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

//go:build unit

package validate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestMergePolicyConfigs_NoOverlays(t *testing.T) {
	base := `
sources:
  - policy:
      - "git::https://example.com/policy"
`

	result, err := MergePolicyConfigs(context.Background(), base, nil)
	require.NoError(t, err)
	assert.Equal(t, base, result)
}

func TestMergePolicyConfigs_SimpleOverlay(t *testing.T) {
	base := `
sources:
  - policy:
      - "git::https://example.com/policy"
`

	overlay := `
exclude:
  - rule1
  - rule2
`

	result, err := MergePolicyConfigs(context.Background(), base, []string{overlay})
	require.NoError(t, err)

	var resultData map[string]interface{}
	err = yaml.Unmarshal([]byte(result), &resultData)
	require.NoError(t, err)

	// Should have both sources and exclude
	assert.Contains(t, resultData, "sources")
	assert.Contains(t, resultData, "exclude")

	// Exclude should have both rules
	exclude := resultData["exclude"].([]interface{})
	assert.Len(t, exclude, 2)
}

func TestMergePolicyConfigs_MergeRuleData(t *testing.T) {
	base := `
ruleData:
  baseKey: baseValue
  sharedKey: baseSharedValue
`

	overlay := `
ruleData:
  overlayKey: overlayValue
  sharedKey: overlaySharedValue
`

	result, err := MergePolicyConfigs(context.Background(), base, []string{overlay})
	require.NoError(t, err)

	var resultData map[string]interface{}
	err = yaml.Unmarshal([]byte(result), &resultData)
	require.NoError(t, err)

	ruleData := resultData["ruleData"].(map[string]interface{})

	// Should have all three keys
	assert.Equal(t, "baseValue", ruleData["baseKey"])
	assert.Equal(t, "overlayValue", ruleData["overlayKey"])
	// Shared key should be overridden by overlay
	assert.Equal(t, "overlaySharedValue", ruleData["sharedKey"])
}

func TestMergePolicyConfigs_ConcatenateArrays(t *testing.T) {
	base := `
exclude:
  - rule1
  - rule2
`

	overlay := `
exclude:
  - rule3
  - rule4
`

	result, err := MergePolicyConfigs(context.Background(), base, []string{overlay})
	require.NoError(t, err)

	var resultData map[string]interface{}
	err = yaml.Unmarshal([]byte(result), &resultData)
	require.NoError(t, err)

	exclude := resultData["exclude"].([]interface{})
	assert.Len(t, exclude, 4)
	assert.Equal(t, "rule1", exclude[0])
	assert.Equal(t, "rule2", exclude[1])
	assert.Equal(t, "rule3", exclude[2])
	assert.Equal(t, "rule4", exclude[3])
}

func TestMergePolicyConfigs_MultipleOverlays(t *testing.T) {
	base := `
sources:
  - policy:
      - "git::https://example.com/policy"
exclude:
  - rule1
`

	overlay1 := `
exclude:
  - rule2
ruleData:
  key1: value1
`

	overlay2 := `
exclude:
  - rule3
ruleData:
  key2: value2
`

	result, err := MergePolicyConfigs(context.Background(), base, []string{overlay1, overlay2})
	require.NoError(t, err)

	var resultData map[string]interface{}
	err = yaml.Unmarshal([]byte(result), &resultData)
	require.NoError(t, err)

	// Should have sources
	assert.Contains(t, resultData, "sources")

	// Should have all three excluded rules
	exclude := resultData["exclude"].([]interface{})
	assert.Len(t, exclude, 3)

	// Should have both ruleData keys
	ruleData := resultData["ruleData"].(map[string]interface{})
	assert.Equal(t, "value1", ruleData["key1"])
	assert.Equal(t, "value2", ruleData["key2"])
}

func TestMergePolicyConfigs_InvalidBase(t *testing.T) {
	base := `{invalid yaml`
	overlay := `exclude: [rule1]`

	_, err := MergePolicyConfigs(context.Background(), base, []string{overlay})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse base policy config")
}

func TestMergePolicyConfigs_InvalidOverlay(t *testing.T) {
	base := `sources: []`
	overlay := `{invalid yaml`

	_, err := MergePolicyConfigs(context.Background(), base, []string{overlay})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse policy overlay")
}

func TestDeepMerge_NestedMaps(t *testing.T) {
	base := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"key1": "base1",
				"key2": "base2",
			},
		},
	}

	overlay := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"key2": "overlay2",
				"key3": "overlay3",
			},
		},
	}

	result := deepMerge(base, overlay)

	level2 := result["level1"].(map[string]interface{})["level2"].(map[string]interface{})
	assert.Equal(t, "base1", level2["key1"])
	assert.Equal(t, "overlay2", level2["key2"])
	assert.Equal(t, "overlay3", level2["key3"])
}
