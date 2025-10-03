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
	"io/fs"
	"os"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
)

var valid = []byte(`{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "subject_name",
      "digest": {
        "sha512": "abcdef0123456789"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "uri:val"
    },
	"buildType": "uri:val"
  }
}`)

func TestMain(t *testing.M) {
	v := t.Run()

	// After all tests have run `go-snaps` can check for not used snapshots
	_, err := snaps.Clean(t)
	if err != nil {
		fmt.Printf("snaps.Clean error: %v\n", err)
	}

	os.Exit(v)
}

func check(t *testing.T, patches ...string) {
	for i, patch := range patches {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			j, err := jsonpatch.MergePatch(valid, []byte(patch))
			assert.NoError(t, err)

			var v any
			err = json.Unmarshal(j, &v)
			assert.NoError(t, err)

			err = SLSA_Provenance_v0_2.Validate(v)
			snaps.MatchSnapshot(t, err)
		})
	}
}

func TestTypeMustBeInToto(t *testing.T) {
	check(t,
		`{"_type": null}`,
		`{"_type": ""}`,
		`{"_type": "something else"}`,
		`{"_type": "https://in-toto.io/Statement/v0.1"}`,
	)
}

func TestSubjectMustBeProvided(t *testing.T) {
	check(t,
		`{"subject": null}`,
		`{"subject": []}`,
		`{"subject": [{"name": null, "digest": null}]}`,
		`{"subject": [{"name": "", "digest": null}]}`,
		`{"subject": [{"name": "a", "digest": {"foo": "abcdef0123456789"}}]}`,
		`{"subject": [{"name": "a", "digest": {"sha256": ""}}]}`,
		`{"subject": [{"name": "a", "digest": {"sha256": "g%-A"}}]}`,
	)
}

func TestTypeMustBeSLSAProvenancev02(t *testing.T) {
	check(t,
		`{"predicateType": null}`,
		`{"predicateType": ""}`,
		`{"predicateType": "something else"}`,
		`{"predicateType": "https://slsa.dev/provenance/v0.2"}`,
	)
}

func TestPredicateBuilderId(t *testing.T) {
	check(t,
		`{"predicate": {"builder": {"id": null}}}`,
		`{"predicate": {"builder": {"id": ""}}}`,
		`{"predicate": {"builder": {"id": "not_uri"}}}`,
		`{"predicate": {"builder": {"id": "scheme:authority"}}}`,
	)
}

func TestPredicateBuilderType(t *testing.T) {
	check(t,
		`{"predicate": {"buildType": null}}`,
		`{"predicate": {"buildType": ""}}`,
		`{"predicate": {"buildType": "not_uri"}}`,
		`{"predicate": {"buildType": "scheme:authority"}}`,
	)
}

func TestPredicateInvocationConfigSourceUri(t *testing.T) {
	check(t,
		`{"predicate": {"invocation": {"configSource": {"uri": null}}}}`, // is optional, so `null` is allowed
		// Values without a scheme are currently allowed due to https://github.com/tektoncd/chains/issues/934.
		`{"predicate": {"invocation": {"configSource": {"uri": ""}}}}`,
		`{"predicate": {"invocation": {"configSource": {"uri": "not_uri"}}}}`,
		`{"predicate": {"invocation": {"configSource": {"uri": "scheme:authority"}}}}`,
	)
}

func TestPredicateInvocationConfigSourceDigest(t *testing.T) {
	check(t,
		`{"predicate": {"invocation": {"configSource": {"digest": null}}}}`, // is optional, so `null` is allowed
		`{"predicate": {"invocation": {"configSource": {"digest": {"foo": "abcdef0123456789"}}}}}`,
		`{"predicate": {"invocation": {"configSource": {"digest": {"sha256": ""}}}}}`,
		`{"predicate": {"invocation": {"configSource": {"digest": {"sha256": "g%-A"}}}}}`,
		`{"predicate": {"invocation": {"configSource": {"digest": {"sha256": "abcdef0123456789"}}}}}`,
	)
}

func TestPredicateInvocationConfigSourceEntryPoint(t *testing.T) {
	check(t,
		`{"predicate": {"invocation": {"configSource": {"entryPoint": null}}}}`, // is optional, so `null` is allowed
		`{"predicate": {"invocation": {"configSource": {"entryPoint": ""}}}}`,
		`{"predicate": {"invocation": {"configSource": {"entryPoint": 1}}}}`,
		`{"predicate": {"invocation": {"configSource": {"entryPoint": "something"}}}}`,
	)
}

func TestPredicateInvocationParameters(t *testing.T) {
	check(t,
		`{"predicate": {"invocation": {"parameters": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"invocation": {"parameters": 1}}}`,
		`{"predicate": {"invocation": {"parameters": {"key1": 1, "key2": "val2"}}}}`,
	)
}

func TestPredicateInvocationEnvironment(t *testing.T) {
	check(t,
		`{"predicate": {"invocation": {"environment": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"invocation": {"environment": 1}}}`,
		`{"predicate": {"invocation": {"environment": {"key1": 1, "key2": "val2"}}}}`,
	)
}

func TestPredicateMetadata(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": null}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": 1}}`,
	)
}

func TestPredicateMetadataBuildInvocationId(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"buildInvocationId": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"buildInvocationId": ""}}}`,
		`{"predicate": {"metadata": {"buildInvocationId": 1}}}`,
		`{"predicate": {"metadata": {"buildInvocationId": "abc"}}}`,
	)
}

func TestPredicateMetadataBuildStartedOn(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"buildStartedOn": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"buildStartedOn": ""}}}`,
		`{"predicate": {"metadata": {"buildStartedOn": 1}}}`,
		`{"predicate": {"metadata": {"buildStartedOn": "1937-01-01T12:00:27.87+00:20"}}}`,
		`{"predicate": {"metadata": {"buildStartedOn": "1985-04-12T23:20:50.52Z"}}}`,
	)
}

func TestPredicateMetadataBuildFinishedOn(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"buildFinishedOn": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"buildFinishedOn": ""}}}`,
		`{"predicate": {"metadata": {"buildFinishedOn": 1}}}`,
		`{"predicate": {"metadata": {"buildFinishedOn": "1937-01-01T12:00:27.87+00:20"}}}`,
		`{"predicate": {"metadata": {"buildFinishedOn": "1985-04-12T23:20:50.52Z"}}}`,
	)
}

func TestPredicateMetadataCompleteness(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"completeness": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"completeness": 1}}}`,
		`{"predicate": {"metadata": {"completeness": {}}}}`,
		`{"predicate": {"metadata": {"completeness": {"a": 1, "b": "c"}}}}`,
	)
}

func TestPredicateMetadataCompletenessParameters(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"completeness": {"parameters": null}}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"completeness": {"parameters": 1}}}}`,
		`{"predicate": {"metadata": {"completeness": {"parameters": true}}}}`,
		`{"predicate": {"metadata": {"completeness": {"parameters": false}}}}`,
	)
}

func TestPredicateMetadataCompletenessEnvironment(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"completeness": {"environment": null}}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"completeness": {"environment": 1}}}}`,
		`{"predicate": {"metadata": {"completeness": {"environment": true}}}}`,
		`{"predicate": {"metadata": {"completeness": {"environment": false}}}}`,
	)
}

func TestPredicateMetadataCompletenessMaterials(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"completeness": {"materials": null}}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"completeness": {"materials": 1}}}}`,
		`{"predicate": {"metadata": {"completeness": {"materials": true}}}}`,
		`{"predicate": {"metadata": {"completeness": {"materials": false}}}}`,
	)
}

func TestPredicateMetadataReproducible(t *testing.T) {
	check(t,
		`{"predicate": {"metadata": {"reproducible": null}}}`, // is optional, so `null` is allowed
		`{"predicate": {"metadata": {"reproducible": 1}}}`,
		`{"predicate": {"metadata": {"reproducible": true}}}`,
		`{"predicate": {"metadata": {"reproducible": false}}}`,
	)
}

func TestPredicateBuildConfig(t *testing.T) {
	check(t,
		`{"predicate": {"buildConfig": null}}`, // is optional, so `null` is allowed
		`{"predicate": {"buildConfig": 1}}`,
		`{"predicate": {"buildConfig": {}}}`,
		`{"predicate": {"buildConfig": {"a": 1, "b": "c"}}}`,
	)
}

func TestPredicateMaterials(t *testing.T) {
	check(t,
		`{"predicate": {"materials": null}}`, // is optional, so `null` is allowed
		`{"predicate": {"materials": 1}}`,
		`{"predicate": {"materials": {}}}`,
		`{"predicate": {"materials": []}}`,
		`{"predicate": {"materials": [{}, {}]}}`,
	)
}

func TestPredicateMaterialsUri(t *testing.T) {
	check(t,
		`{"predicate": {"materials": [{"uri": null}]}}`, // is optional, so `null` is allowed
		`{"predicate": {"materials": [{"uri": ""}]}}`,
		`{"predicate": {"materials": [{"uri": "not_uri"}]}}`,
		`{"predicate": {"materials": [{"uri": "scheme:authority"}]}}`,
	)
}

func TestPredicateMaterialsDigest(t *testing.T) {
	check(t,
		`{"predicate": {"materials": [{"digest": null}]}}`, // is optional, so `null` is allowed
		`{"predicate": {"materials": [{"digest": {"foo": "abcdef0123456789"}}]}}`,
		`{"predicate": {"materials": [{"digest": {"sha256": ""}}]}}`,
		`{"predicate": {"materials": [{"digest": {"sha256": "g%-A"}}]}}`,
		`{"predicate": {"materials": [{"digest": {"sha256": "abcdef"}}]}}`,
	)
}

func TestExamples(t *testing.T) {
	err := fs.WalkDir(os.DirFS("."), "examples", func(path string, d fs.DirEntry, err error) error {
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			j, err := os.ReadFile(path)
			assert.NoError(t, err)

			var v any
			err = json.Unmarshal(j, &v)
			assert.NoError(t, err)

			err = SLSA_Provenance_v0_2.Validate(v)
			valid := strings.HasSuffix(path, "_valid.json")

			if valid {
				assert.Nil(t, err)
			} else {
				snaps.MatchSnapshot(t, err)
			}
		})

		return nil
	})

	assert.NoError(t, err)
}
