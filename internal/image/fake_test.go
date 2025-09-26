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

package image

import (
	"encoding/json"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/signature"
)

func TestFakeAttStatement(t *testing.T) {
	tests := []struct {
		name      string
		statement in_toto.ProvenanceStatementSLSA02
		want      string
		wantPanic bool
	}{
		{
			name: "empty statement",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":null,"predicate":{"builder":{"id":""},"buildType":"","invocation":{"configSource":{}}}}`,
		},
		{
			name: "statement with subject",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
					Subject: []in_toto.Subject{
						{
							Name:   "example.com/repo:tag",
							Digest: map[string]string{"sha256": "abc123"},
						},
					},
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"example.com/repo:tag","digest":{"sha256":"abc123"}}],"predicate":{"builder":{"id":""},"buildType":"","invocation":{"configSource":{}}}}`,
		},
		{
			name: "statement with predicate",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
				},
				Predicate: v02.ProvenancePredicate{
					BuildType: "https://example.com/build",
					Builder: common.ProvenanceBuilder{
						ID: "https://example.com/builder",
					},
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":null,"predicate":{"buildType":"https://example.com/build","builder":{"id":"https://example.com/builder"},"invocation":{"configSource":{}}}}`,
		},
		{
			name: "complete statement with all fields",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
					Subject: []in_toto.Subject{
						{
							Name:   "example.com/repo:latest",
							Digest: map[string]string{"sha256": "def456"},
						},
					},
				},
				Predicate: v02.ProvenancePredicate{
					BuildType: "https://example.com/build",
					Builder: common.ProvenanceBuilder{
						ID: "https://example.com/builder",
					},
					Invocation: v02.ProvenanceInvocation{
						ConfigSource: v02.ConfigSource{
							URI: "https://example.com/config",
						},
					},
					BuildConfig: map[string]interface{}{
						"key": "value",
					},
					Metadata: &v02.ProvenanceMetadata{
						BuildInvocationID: "build-123",
					},
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"example.com/repo:latest","digest":{"sha256":"def456"}}],"predicate":{"builder":{"id":"https://example.com/builder"},"buildType":"https://example.com/build","invocation":{"configSource":{"uri":"https://example.com/config"}},"buildConfig":{"key":"value"},"metadata":{"buildInvocationID":"build-123","completeness":{"parameters":false,"environment":false,"materials":false},"reproducible":false}}}`,
		},
		{
			name: "statement with multiple subjects",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
					Subject: []in_toto.Subject{
						{
							Name:   "example.com/app:v1.0.0",
							Digest: map[string]string{"sha256": "abc123"},
						},
						{
							Name:   "example.com/app:latest",
							Digest: map[string]string{"sha256": "abc123"},
						},
					},
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"example.com/app:v1.0.0","digest":{"sha256":"abc123"}},{"name":"example.com/app:latest","digest":{"sha256":"abc123"}}],"predicate":{"builder":{"id":""},"buildType":"","invocation":{"configSource":{}}}}`,
		},
		{
			name: "statement with complex build config",
			statement: in_toto.ProvenanceStatementSLSA02{
				StatementHeader: in_toto.StatementHeader{
					Type:          in_toto.StatementInTotoV01,
					PredicateType: v02.PredicateSLSAProvenance,
				},
				Predicate: v02.ProvenancePredicate{
					BuildType: "https://tekton.dev/chains/v2",
					Builder: common.ProvenanceBuilder{
						ID: "https://tekton.dev/chains/v2",
					},
					BuildConfig: map[string]interface{}{
						"tasks": []map[string]interface{}{
							{
								"name": "build-task",
								"ref":  map[string]string{"name": "buildah", "kind": "ClusterTask"},
							},
						},
						"params": map[string]string{
							"IMAGE": "quay.io/example/app",
						},
					},
				},
			},
			want: `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":null,"predicate":{"builder":{"id":"https://tekton.dev/chains/v2"},"buildType":"https://tekton.dev/chains/v2","invocation":{"configSource":{}},"buildConfig":{"params":{"IMAGE":"quay.io/example/app"},"tasks":[{"name":"build-task","ref":{"kind":"ClusterTask","name":"buildah"}}]}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := fakeAtt{statement: tt.statement}

			if tt.wantPanic {
				assert.Panics(t, func() {
					fake.Statement()
				})
				return
			}

			got := fake.Statement()

			// Verify that the result is valid JSON
			var result map[string]interface{}
			err := json.Unmarshal(got, &result)
			require.NoError(t, err, "Statement() should return valid JSON")

			// Verify the JSON content matches expected
			assert.JSONEq(t, tt.want, string(got), "Statement() should return expected JSON")

			// Additional validations for JSON structure
			assert.Contains(t, result, "_type", "JSON should contain _type field")
			assert.Contains(t, result, "predicateType", "JSON should contain predicateType field")
			assert.Contains(t, result, "predicate", "JSON should contain predicate field")

			// Verify core field values
			assert.Equal(t, in_toto.StatementInTotoV01, result["_type"], "_type should match expected value")
			assert.Equal(t, v02.PredicateSLSAProvenance, result["predicateType"], "predicateType should match expected value")

			// Verify the result is not empty
			assert.NotEmpty(t, got, "Statement() should not return empty JSON")
		})
	}
}

func TestFakeAttGetterMethods(t *testing.T) {
	// Test all the simple getter methods in a single comprehensive test
	fake := fakeAtt{}

	t.Run("Type", func(t *testing.T) {
		got := fake.Type()
		want := in_toto.StatementInTotoV01
		assert.Equal(t, want, got, "Type() should return expected value")
		assert.NotEmpty(t, got, "Type() should not return empty string")
	})

	t.Run("PredicateType", func(t *testing.T) {
		got := fake.PredicateType()
		want := v02.PredicateSLSAProvenance
		assert.Equal(t, want, got, "PredicateType() should return expected value")
		assert.NotEmpty(t, got, "PredicateType() should not return empty string")
		assert.Contains(t, got, "https://", "PredicateType() should be a valid URL")
	})

	t.Run("Signatures", func(t *testing.T) {
		got := fake.Signatures()
		want := []signature.EntitySignature{}
		assert.Equal(t, want, got, "Signatures() should return expected value")
		assert.NotNil(t, got, "Signatures() should not return nil")
		assert.Len(t, got, 0, "Signatures() should return empty slice")
	})

	t.Run("Subject", func(t *testing.T) {
		got := fake.Subject()
		want := []in_toto.Subject{}
		assert.Equal(t, want, got, "Subject() should return expected value")
		assert.NotNil(t, got, "Subject() should not return nil")
		assert.Len(t, got, 0, "Subject() should return empty slice")
	})
}
