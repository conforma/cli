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

package schema

import (
	_ "embed"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed slsa_provenance_v0.2.json
var slsa_provenance_v0_2_json string

var SLSA_Provenance_v0_2 *jsonschema.Schema

var SLSA_Provenance_v0_2_URI = "https://slsa.dev/provenance/v0.2"

func init() {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true

	if err := compiler.AddResource(SLSA_Provenance_v0_2_URI, strings.NewReader(slsa_provenance_v0_2_json)); err != nil {
		panic(err)
	}
	SLSA_Provenance_v0_2 = compiler.MustCompile(SLSA_Provenance_v0_2_URI)
}
