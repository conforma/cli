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
	"fmt"
	"os"
	"path"
	"reflect"

	"github.com/conforma/cli/api/v1alpha1"
	"github.com/invopop/jsonschema"
	"github.com/spf13/afero"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

var (
	jsonType = reflect.TypeOf(extv1.JSON{})
)

func main() {
	// Write the JSON schema to a file location provided
	if len(os.Args) < 3 {
		fmt.Printf(`
Please ensure you've provided the following:
  * A directory location to write the JSON schema to.
    The file will be titled schema.json
  * A repository for the Go source file containing the struct used in schema creation."
  * The path to the directory containing the Go source file which contains the struct used for schema creation.
    Example: go run schema/export.go /tmp/conforma-cli github.com/conforma/cli ./api/v1alpha1/

`)
		os.Exit(1)
	}
	schemaDir := os.Args[1]
	repo := os.Args[2]
	sourceFilePath := os.Args[3]
	fileName := "policy_spec.json"
	if len(os.Args) == 5 {
		fileName = os.Args[4]
	}
	// Create a JSON schema from a Go type
	schema, err := JsonSchemaFromPolicySpec(&v1alpha1.EnterpriseContractPolicySpec{}, repo, sourceFilePath)
	if err != nil {
		fmt.Println("Error creating JSON schema:", err)
		os.Exit(1)
	}
	// Write the JSON schema to a file location provided
	err = writeSchemaToFile(schemaDir, schema, fileName)
	if err != nil {
		fmt.Println("Error writing JSON schema to file:", err)
		os.Exit(1)
	}
	fmt.Println("JSON schema written to", path.Join(schemaDir, fileName))
}

// Write the JSON schema to a directory location provided
func writeSchemaToFile(schemaDir string, schema []byte, fileName string) error {
	fs := afero.NewOsFs()
	fs.MkdirAll(schemaDir, 0755)
	return afero.WriteFile(fs, path.Join(schemaDir, fileName), schema, 0644)
}

// Create a JSON schema from a Go type, and return the JSON as a byte slice
func JsonSchemaFromPolicySpec(ecp *v1alpha1.EnterpriseContractPolicySpec, repo, dir string) ([]byte, error) {
	// Create a JSON schema from a Go type
	r := jsonschema.Reflector{}
	if err := r.AddGoComments(repo, dir); err != nil {
		return nil, err
	}
	schema := r.Reflect(ecp)

	// allow any property in the "JSON" type definition
	schema.Definitions["JSON"].AdditionalProperties = jsonschema.TrueSchema

	prettyJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, err
	}
	return prettyJSON, nil
}
