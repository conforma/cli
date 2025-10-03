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

package utils

import (
	"bytes"
	"embed"
	_ "embed"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test_templates/*.tmpl
var testTemplatesFS embed.FS

func TestSetupTemplate(t *testing.T) {
	tmpl, err := SetupTemplate(testTemplatesFS)
	assert.NoError(t, err)

	tests := []struct {
		main     string
		expected string
		input    map[string]string
	}{
		{
			input:    map[string]string{"name": "friend"},
			expected: "✓ Hello and greetings, friend.\n\n",
		},
		{
			main:     "main.tmpl",
			expected: "✓ Hello and greetings, spam.\n\n",
			input:    map[string]string{"name": "spam"},
		},
		{
			main:     "_name.tmpl",
			expected: "and hola, amigo.\n",
			input:    map[string]string{"greeting": "hola", "name": "amigo"},
		},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		var err error
		if tt.main == "" {
			err = tmpl.Execute(&buf, tt.input)
			assert.NoError(t, err)
		} else {
			err = tmpl.ExecuteTemplate(&buf, tt.main, tt.input)
			assert.NoError(t, err)
		}
		assert.Equal(t, tt.expected, buf.String())
	}
}

func TestTemplateHelpers(t *testing.T) {
	tmpl, err := SetupTemplate(testTemplatesFS)
	assert.NoError(t, err)

	tests := []struct {
		main        string
		expected    string
		expectedErr error
		input       map[string]interface{}
	}{
		{
			main: "helpers.tmpl",
			input: map[string]interface{}{
				"colorText": map[string]interface{}{
					"color": "success",
					"str":   "color test",
				},
				"indicator": map[string]interface{}{
					"color": "warning",
				},
				"colorIndicator": map[string]interface{}{
					"color": "violation",
				},
				"wrap": map[string]interface{}{
					"width": 3,
					"s":     "wrapped string",
				},
				"indent": map[string]interface{}{
					"n": 3,
					"s": "indentation test",
				},
				"indentWrap": map[string]interface{}{
					"n":     3,
					"width": 10,
					"s":     "indent wrapped test",
				},
				"toMap": map[string]interface{}{
					"k1": "key1",
					"v1": "value1",
					"k2": "key2",
					"v2": "value2",
				},
				"isString": map[string]interface{}{
					"value": "str",
				},
				"joinStrSlice": map[string]interface{}{
					"slice": []interface{}{"one", "two", "three"},
					"sep":   ",",
				},
			},
			expected:    "color test\n›indicator\n✕colorIndicator\nwrapped\nstring\n   indentation test\n   indent\n   wrapped\n   test\nkey1: value1\nkey2: value2\n\ntrue\none,two,three",
			expectedErr: nil,
		},
		{
			main: "helpers.tmpl",
			input: map[string]interface{}{
				"colorText": map[string]interface{}{
					"color": "another",
					"str":   "color test",
				},
				"isString": map[string]interface{}{
					"value": 2,
				},
			},
			expected:    "color test\nfalse\n",
			expectedErr: nil,
		},
		{
			main: "helpers.tmpl",
			input: map[string]interface{}{
				"joinStrSlice": map[string]interface{}{
					"slice": []interface{}{1, 2, 3},
					"sep":   ",",
				},
			},
			expected:    "",
			expectedErr: errors.New("joinStrSlice argument must be a slice of strings"),
		},
		{
			main: "helpers.tmpl",
			input: map[string]interface{}{
				"toMap": map[string]interface{}{
					"k1": 1,
					"v1": "value1",
					"k2": 2,
					"v2": "value2",
				},
			},
			expected:    "",
			expectedErr: errors.New("toMap keys must be strings"),
		},
	}
	for _, tt := range tests {
		var buf bytes.Buffer

		SetColorEnabled(true, false)
		err := tmpl.ExecuteTemplate(&buf, tt.main, tt.input)

		if tt.expectedErr != nil {
			assert.ErrorContains(t, err, tt.expectedErr.Error())
		} else {
			assert.Nil(t, err)
		}
		assert.Equal(t, tt.expected, buf.String())
	}
}
