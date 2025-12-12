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

package schema

import (
	"encoding/json"
	"fmt"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
)

var validV1 = []byte(`{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "subject_name",
      "digest": {
        "sha512": "abcdef0123456789"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "uri:val",
      "externalParameters": {}
    },
    "runDetails": {
      "builder": {
        "id": "uri:val"
      }
    }
  }
}`)

func checkV1(t *testing.T, patches ...string) {
	for i, patch := range patches {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			j, err := jsonpatch.MergePatch(validV1, []byte(patch))
			assert.NoError(t, err)

			var v any
			err = json.Unmarshal(j, &v)
			assert.NoError(t, err)

			err = SLSA_Provenance_v1.Validate(v)
			snaps.MatchSnapshot(t, err)
		})
	}
}

func TestV1TypeMustBeInToto(t *testing.T) {
	checkV1(t,
		`{"_type": null}`,
		`{"_type": ""}`,
		`{"_type": "something else"}`,
		`{"_type": "https://in-toto.io/Statement/v0.1"}`,
	)
}

func TestV1SubjectMustBeProvided(t *testing.T) {
	checkV1(t,
		`{"subject": null}`,
		`{"subject": []}`,
		`{"subject": [{"name": null, "digest": null}]}`,
		`{"subject": [{"name": "", "digest": null}]}`,
		`{"subject": [{"name": "a", "digest": {"foo": "abcdef0123456789"}}]}`,
		`{"subject": [{"name": "a", "digest": {"sha256": ""}}]}`,
		`{"subject": [{"name": "a", "digest": {"sha256": "g%-A"}}]}`,
	)
}

func TestV1PredicateTypeMustBeSLSAProvenancev1(t *testing.T) {
	checkV1(t,
		`{"predicateType": null}`,
		`{"predicateType": ""}`,
		`{"predicateType": "something else"}`,
		`{"predicateType": "https://slsa.dev/provenance/v1"}`,
	)
}

func TestV1BuildDefinitionBuildType(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"buildType": null}}}`,
		`{"predicate": {"buildDefinition": {"buildType": ""}}}`,
		`{"predicate": {"buildDefinition": {"buildType": "not_uri"}}}`,
		`{"predicate": {"buildDefinition": {"buildType": "scheme:authority"}}}`,
	)
}

func TestV1BuildDefinitionExternalParameters(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"externalParameters": null}}}`,
		`{"predicate": {"buildDefinition": {"externalParameters": 1}}}`,
		`{"predicate": {"buildDefinition": {"externalParameters": {}}}}`,
		`{"predicate": {"buildDefinition": {"externalParameters": {"key": "value"}}}}`,
	)
}

func TestV1BuildDefinitionInternalParameters(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"internalParameters": null}}}`,
		`{"predicate": {"buildDefinition": {"internalParameters": 1}}}`,
		`{"predicate": {"buildDefinition": {"internalParameters": {}}}}`,
		`{"predicate": {"buildDefinition": {"internalParameters": {"key": "value"}}}}`,
	)
}

func TestV1BuildDefinitionResolvedDependencies(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": null}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": 1}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": {}}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": []}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{}, {}]}}}`,
	)
}

func TestV1BuildDefinitionResolvedDependenciesUri(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": null}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": ""}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": "not_uri"}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": "scheme:authority"}]}}}`,
	)
}

func TestV1BuildDefinitionResolvedDependenciesDigest(t *testing.T) {
	checkV1(t,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": null}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"foo": "abcdef0123456789"}}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"sha256": ""}}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"sha256": "g%-A"}}]}}}`,
		`{"predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"sha256": "abcdef0123456789"}}]}}}`,
	)
}

func TestV1RunDetailsBuilder(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"builder": null}}}`,
		`{"predicate": {"runDetails": {"builder": {}}}}`,
		`{"predicate": {"runDetails": {"builder": {"id": null}}}}`,
		`{"predicate": {"runDetails": {"builder": {"id": ""}}}}`,
		`{"predicate": {"runDetails": {"builder": {"id": "not_uri"}}}}`,
		`{"predicate": {"runDetails": {"builder": {"id": "scheme:authority"}}}}`,
	)
}

func TestV1RunDetailsMetadata(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"metadata": null}}}`,
		`{"predicate": {"runDetails": {"metadata": 1}}}`,
		`{"predicate": {"runDetails": {"metadata": {}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"invocationId": "abc"}}}}`,
	)
}

func TestV1RunDetailsMetadataInvocationId(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"metadata": {"invocationId": null}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"invocationId": ""}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"invocationId": 1}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"invocationId": "abc"}}}}`,
	)
}

func TestV1RunDetailsMetadataStartedOn(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"metadata": {"startedOn": null}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"startedOn": ""}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"startedOn": 1}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"startedOn": "1937-01-01T12:00:27.87+00:20"}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"startedOn": "1985-04-12T23:20:50.52Z"}}}}`,
	)
}

func TestV1RunDetailsMetadataFinishedOn(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"metadata": {"finishedOn": null}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"finishedOn": ""}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"finishedOn": 1}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"finishedOn": "1937-01-01T12:00:27.87+00:20"}}}}`,
		`{"predicate": {"runDetails": {"metadata": {"finishedOn": "1985-04-12T23:20:50.52Z"}}}}`,
	)
}

func TestV1RunDetailsByproducts(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"byproducts": null}}}`,
		`{"predicate": {"runDetails": {"byproducts": 1}}}`,
		`{"predicate": {"runDetails": {"byproducts": {}}}}`,
		`{"predicate": {"runDetails": {"byproducts": []}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{}, {}]}}}`,
	)
}

func TestV1RunDetailsByproductsUri(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"byproducts": [{"uri": null}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"uri": ""}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"uri": "not_uri"}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"uri": "scheme:authority"}]}}}`,
	)
}

func TestV1RunDetailsByproductsDigest(t *testing.T) {
	checkV1(t,
		`{"predicate": {"runDetails": {"byproducts": [{"digest": null}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"digest": {"foo": "abcdef0123456789"}}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"digest": {"sha256": ""}}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"digest": {"sha256": "g%-A"}}]}}}`,
		`{"predicate": {"runDetails": {"byproducts": [{"digest": {"sha256": "abcdef0123456789"}}]}}}`,
	)
}
